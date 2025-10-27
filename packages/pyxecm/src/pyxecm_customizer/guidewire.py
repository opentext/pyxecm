"""Guidewire Module to interact with the Guidewire REST API ("Cloud API").

See:
https://www.guidewire.com/de/developers/apis/cloud-apis
https://docs.guidewire.com/cloud/pc/202407/apiref/
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import platform
import sys
import urllib.parse
from importlib.metadata import version

import requests
from requests.auth import HTTPBasicAuth

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".customizer.guidewire"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

default_logger = logging.getLogger(MODULE_NAME)


class Guidewire:
    """Class Guidewire is used to retrieve and automate stettings and objects in Guidewire."""

    _config: dict
    _scope = None
    _access_token = None
    logger: logging.Logger = default_logger

    def __init__(
        self,
        base_url: str,
        as_url: str,
        auth_type: str = "",
        client_id: str = "",
        client_secret: str = "",
        username: str = "",
        password: str = "",
        scope: str = "",
        token_url: str = "",
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the Guidewire API client.

        Args:
            base_url (str):
                The base URL of the Guidewire Cloud API.
            as_url (str):
                The application server endpount the Guidewire system.
            auth_type (str):
                The authorization type, either "oauth" or "basic".
            client_id (str, optional):
                The Client ID for authentication (required for client credential flow).
            client_secret (str, optional):
                The Client Secret for authentication (required for client credential flow).
            username (str, optional):
                The username for authentication (required for password-based authentication).
            password (str, optional):
                The password for authentication (required for password-based authentication).
            scope (str, optional):
                The OAuth2 scope(s). Multiple scopes needs to be separated by spaces.
                Typical scopes for Guidewire:
                    "grantedAuthorities",
                    "groups",
                    "openid",
                    "profile",
                    "email",
                    "address",
                    "phone",
                    "offline_access",
                    "device_sso"
                You can get the IDP configuration via the IDP URL - like this for OKTA:
                https://guidewire-hub.okta.com/oauth2/default/.well-known/openid-configuration
            token_url (str, optional):
                If native OAuth2 is not enabled in Guidewire but an external IDP (like OKTA) ist used
                then the IDP token URL can to be provided via this parameter.
            logger:
                The logging object used for all log messages. Default is default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("guidewire")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        self._scope = scope

        guidewire_config = {}
        # Store the credentials and parameters in a config dictionary:
        guidewire_config["baseUrl"] = base_url.rstrip("/")
        guidewire_config["asUrl"] = as_url.rstrip("/")
        guidewire_config["authType"] = auth_type
        guidewire_config["clientId"] = client_id
        guidewire_config["clientSecret"] = client_secret
        guidewire_config["username"] = username
        guidewire_config["password"] = password
        guidewire_config["restUrl"] = (
            guidewire_config["baseUrl"] + "/rest"
            if guidewire_config["baseUrl"]
            else guidewire_config["asUrl"] + "/rest"
        )
        if token_url:
            guidewire_config["tokenUrl"] = token_url
        else:
            guidewire_config["tokenUrl"] = (
                guidewire_config["baseUrl"] + "/oauth2/token"
                if guidewire_config["baseUrl"]
                else guidewire_config["asUrl"] + "/oauth2/token"
            )

        guidewire_config["adminUrl"] = guidewire_config["restUrl"] + "/admin/v1"
        guidewire_config["accountUrl"] = guidewire_config["restUrl"] + "/account/v1"
        guidewire_config["accountSearchUrl"] = guidewire_config["accountUrl"] + "/search/accounts"
        guidewire_config["policyUrl"] = guidewire_config["restUrl"] + "/policy/v1"
        guidewire_config["policySearchUrl"] = guidewire_config["policyUrl"] + "/search/policies"
        guidewire_config["claimUrl"] = guidewire_config["restUrl"] + "/claim/v1"
        guidewire_config["claimSearchUrl"] = guidewire_config["claimUrl"] + "/search/claims-v2"

        self._config = guidewire_config

        self._session = requests.Session()

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict:
                The configuration dictionary with all settings.

        """

        return self._config

    # end method definition

    def authenticate(self, auth_type: str | None = None) -> HTTPBasicAuth | str | None:
        """Authenticate with the Guidewire API using either client credentials or username/password.

        Args:
            auth_type (str | None, optional):
                The Authorization type. This can be "basic" or "oauth".

        Returns:
            bool:
                True if authentication is successful, False otherwise.

        """

        header = self.request_header()
        self._session.headers.update(header)

        if auth_type is None:
            auth_type = self.config()["authType"]

        if auth_type == "basic":
            username = self.config()["username"]
            password = self.config()["password"]
            if not self._session:
                self._session = requests.Session()
            self._session.auth = HTTPBasicAuth(username, password)
            return self._session.auth

        request_url = self.config()["tokenUrl"]

        # Check if both Resource Owner credentials (username/password) AND client credentials (clientId/clientSecret) are provided
        if (
            self.config()["username"]
            and self.config()["password"]
            and self.config()["clientId"]
            and self.config()["clientSecret"]
        ):
            # Use the OAuth2 "Resource Owner Password Credentials Grant" (ROPC)
            # This flow is suitable when the application has direct access to the user's credentials (e.g., in highly trusted apps).
            # It's generally discouraged in modern apps due to security concerns.
            # Required parameters:
            # - grant_type: must be "password"
            # - username: the resource owner (user)'s username
            # - password: the resource owner (user)'s password
            # - client_id/client_secret: the app's credentials issued by the authorization server
            auth_data = {
                "grant_type": "password",
                "username": self.config()["username"],
                "password": self.config()["password"],
                "client_id": self.config()["clientId"],  # Required for some OAuth2 flows
                "client_secret": self.config()["clientSecret"],  # Required for some OAuth2 flows
            }
        # If only clientId and clientSecret are provided, use the Client Credentials Grant
        elif self.config()["clientId"] and self.config()["clientSecret"]:
            # Use the OAuth2 "Client Credentials Grant"
            # This flow is used when the application (client) is acting on its own behalf, not on behalf of a user.
            # Suitable for service-to-service interactions or background jobs (no user context).
            # Required parameters:
            # - grant_type: must be "client_credentials"
            # - client_id/client_secret: the app's credentials issued by the authorization server
            auth_data = {
                "grant_type": "client_credentials",
                "client_id": self.config()["clientId"],
                "client_secret": self.config()["clientSecret"],
            }
        # If neither of the above combinations is satisfied, authentication can't proceed
        else:
            # Log an error if required credentials are missing
            # Either username/password AND client credentials (for ROPC)
            # OR just client credentials (for Client Credentials Grant)
            self.logger.error(
                "Authentication of type -> '%s' requires either client credentials or username/password.", auth_type
            )
            return False

        if self._scope:
            auth_data["scope"] = self._scope

        try:
            response = requests.post(request_url, data=auth_data)
            if response.status_code == 200:
                self.token = response.json().get("access_token")
                return True
            else:
                self.logger.error("OAuth2 authentication failed: %s - %s", response.status_code, response.text)
        except requests.RequestException as e:
            self.logger.error("OAuth2 token request failed; error -> %s", str(e))

        return False

    # end method definition

    def request_header(self, content_type: str = "application/json") -> dict:
        """Generate request headers including authentication token.

        Args:
            content_type (str, optional):
                Custom content type for the request.
                Typical value for Guidewire is application/json.

        Returns:
            dict:
                A dictionary containing authorization headers.

        """

        request_header = {
            "User-Agent": USER_AGENT,
            "Content-Type": content_type,
        }

        if self.config()["authType"] == "oauth" and self._access_token:
            request_header["Authorization"] = ("Bearer {}".format(self._access_token),)

        return request_header

    # end method definition

    def do_request(
        self, method: str, url: str, data: dict | None = None, json_data: dict | None = None, params: dict | None = None
    ) -> dict:
        """Send a request to the Guidewire REST API.

        Args:
            method (str):
                The HTTP method to use (GET, POST, PUT, DELETE).
            url (str):
                The API endpoint to call.
            data (dict):
                The request payload (if applicable).
            json_data (dict | None, optional):
                Request payload for the JSON parameter. Defaults to None.
            params (dict):
                The URL parameters (if applicable).

        Returns:
            dict:
                Response as a dictionary.

        """

        response = self._session.request(
            method=method, url=url, headers=self.request_header(), data=data, json=json_data, params=params
        )

        return response.json() if response.content else {}

    # end method definition

    def process_parameters(
        self, fields: list | None = None, filters: list | None = None, page_size: int | None = 25
    ) -> str | None:
        """Determine the request parameters (filters, fields).

        Args:
            fields (list | None, optional):
                List of filter values. Defaults to None.
            filters (list | None, optional):
                List of filter values. Defaults to None.
            page_size (int, optional):
                The maximum number of groups to return.

        Returns:
            str | None:
                Encoded URL parameters for the request URL.

        """

        query = {}

        if fields:
            fields = ",".join(fields)
            query["fields"] = fields

        for filter_dict in filters or []:
            if "op" not in filter_dict:
                filter_dict["op"] = "eq"
            if "attribute" not in filter_dict:
                self.logger.error("Missing attribute in filter condition!")
                return None
            if "value" not in filter_dict:
                self.logger.error("Missing value(s) in filter condition!")
                return None
            elif isinstance(filter_dict["value"], list):
                filter_dict["value"] = ",".join(filter_dict["value"])
            query["filter"] = (
                filter_dict.get("attribute") + ":" + filter_dict.get("op") + ":" + filter_dict.get("value")
            )

        if page_size:
            query["pageSize"] = page_size

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        return encoded_query

    # end method definition

    def get_result_value(
        self,
        response: dict,
        key: str,
        index: int = 0,
        show_error: bool = True,
    ) -> str | None:
        """Read an item value from the Guidewire REST API response.

        Args:
            response (dict):
                Guidewire REST API response object.
            key (str):
                Key to find (e.g., "id", "name").
            index (int, optional):
                Index to use if a list of results is delivered (1st element has index 0).
                Defaults to 0.
            show_error (bool, optional):
                Whether an error or just a warning should be logged. Defaults to True.

        Returns:
            str | None:
                Value of the item with the given key, or None if no value is found.

        """

        # First do some sanity checks:
        if not response:
            self.logger.debug("Empty Guidewire response - no results found!")
            return None

        # To support also iterators that yield from results,
        # we wrap an "attributes" element into a "data" element
        # to make the following code work like for direct REST responses:
        if "attributes" in response:
            response = {"data": response}

        if "data" not in response:
            if show_error:
                self.logger.error("No 'data' key in Guidewire REST response -> %s. Returning None.", str(response))
            return None

        results = response["data"]
        if not results:
            self.logger.debug("No results found in the Guidewire response! Empty 'data' element.")
            return None

        # check if results is a list or a dict (both is possible - iterator responses will be dict):
        if isinstance(results, dict):
            # result is a dict - we don't need index value

            attributes = results.get("attributes", {})
            if key in attributes:
                return attributes[key]
            else:
                self.logger.error(
                    "Key -> '%s' is not in result attributes!",
                    key,
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
            data = results[index]
            attributes = data.get("attributes", {})
            if key not in attributes:
                if show_error:
                    self.logger.error("Key -> '%s' is not in result attributes -> %s!", key, attributes)
                return None
            return attributes[key]
        else:
            self.logger.error(
                "Result needs to be a list or dict but it is -> %s",
                str(type(results)),
            )
            return None

    # end method definition

    def get_groups(
        self,
        fields: list | None = None,
        filters: list | None = None,
        page_size: int = 25,
        next_page_url: str | None = None,
    ) -> dict:
        """Retrieve a list of Guidewire groups.

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - displayName
                - groupType
                - id
                - loadFactor
                - name
                - organization
                - parent
                - securityZone
                - supervisor
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the value to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of groups to return.
            next_page_url (str, optional):
                The Guidewire URL to retrieve the next page of Guidewire groups (pagination).
                This is used for the iterator get_groups_iterator() below.

        Returns:
            dict:
                JSON response containing account data. None in case of an error.

        Example reponse:
        {
            'count': 25,
            'data': [
                {
                    'attributes': {
                        'displayName': 'Actuary Unit',
                        'groupType': {...},
                        'id': 'pc:S_I-NOU3hb3FU0qTfu8fd',
                        'loadFactor': 100,
                        'name': 'Actuary Unit',
                        'organization': {...},
                        'parent': {...},
                        'securityZone': {...},
                        'supervisor': {...}
                    },
                    'checksum': '0',
                    'links': {
                        'self': {...}
                    }
                },
                ...
            ],
            'links': {
                'first': {
                    'href': '/admin/v1/groups?fields=%2Adefault',
                    'methods': ['get']
                },
                'next': {
                    'href': '/admin/v1/groups?fields=%2Adefault&pageOffset=25',
                    'methods': ['get']
                },
                'self': {...}
            }
        }

        """

        if not next_page_url:
            request_url = self.config()["adminUrl"] + "/groups"

            encoded_query = self.process_parameters(fields=fields, filters=filters, page_size=page_size)
            if encoded_query:
                request_url += "?" + encoded_query
        else:
            request_url = self.config()["restUrl"] + next_page_url

        return self.do_request(method="GET", url=request_url)

    # end method definition

    def get_groups_iterator(self, fields: list | None = None, filters: list | None = None, page_size: int = 25) -> iter:
        """Get an iterator object that can be used to traverse all Guidewire groups.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of groups.

        Example usage:
            groups = guidewire_object.get_groups_iterator()
            for group in groups:
                logger.info("Traversing Guidewire group -> '%s'...", group.get("attributes", {}).get("displayName"))

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - displayName
                - groupType
                - id
                - loadFactor
                - name
                - organization
                - parent
                - securityZone
                - supervisor
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the value to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of groups to return.

        Returns:
            iter:
                A generator yielding one Guidewire group per iteration.
                If the REST API fails, returns no value.

        """

        next_page_url = None

        while True:
            response = self.get_groups(fields=fields, filters=filters, page_size=page_size, next_page_url=next_page_url)
            if not response or "data" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["data"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_url = response.get("links", {}).get("next", {}).get("href")
            if not next_page_url:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def get_group(self, group_id: str) -> dict:
        """Retrieve details of a specific group.

        Args:
            group_id:
                The unique identifier of the group.

        Returns:
            dict:
                JSON response containing group details.

        Example response;
        {
            'data': {
                'attributes': {
                    'displayName': 'Actuary Unit',
                    'groupType': {
                        'code': 'actuary',
                        'name': 'Actuary unit'
                    },
                    'id': 'pc:S_I-NOU3hb3FU0qTfu8fd',
                    'loadFactor': 100,
                    'name': 'Actuary Unit',
                    'organization': {
                        'displayName': 'Enigma Fire & Casualty',
                        'id': 'systemTables:1',
                        'type': 'Organization',
                        'uri': '/admin/v1/organizations/systemTables:1'
                    },
                    'parent': {
                        'displayName': 'Enigma Fire & Casualty',
                        'id': 'systemTables:1',
                        'type': 'Group',
                        'uri': '/admin/v1/groups/systemTables:1'
                    },
                    'securityZone': {
                        'displayName': 'HO UW',
                        'id': 'pc:So-lJXKuecOco_hGZ_8iR'
                    },
                    'supervisor': {
                        'displayName': 'Super Visor',
                        'id': 'pc:S1cZ06yduoQadHVOcVCyv',
                        'type': 'User',
                        'uri': '/admin/v1/users/pc:S1cZ06yduoQadHVOcVCyv'
                    }
                },
                'checksum': '0',
                'links': {...}
            }
        }

        """

        request_url = self.config()["adminUrl"] + "/groups/" + str(group_id)

        return self.do_request(method="GET", url=request_url)

    # end method definition

    def get_users(
        self,
        fields: list | None = None,
        filters: list | None = None,
        page_size: int = 25,
        next_page_url: str | None = None,
    ) -> dict:
        """Retrieve a list of Guidewire users.

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - displayName
                - groupType
                - id
                - loadFactor
                - name
                - organization
                - parent
                - securityZone
                - supervisor
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the value to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of groups to return.
            next_page_url (str | None, optional):
                The Guidewire URL to retrieve the next page of Guidewire groups (pagination).
                This is used for the iterator get_groups_iterator() below.

        Returns:
            dict:
                JSON response containing account data.

        Example reponse:
        {
            'count': 10,
            'data': [
                {
                    'attributes': {
                        'active': True,
                        'displayName': 'Alice Applegate',
                        'externalUser': False,
                        'firstName': 'Alice',
                        'groups': [
                            {
                                'displayName': 'Eastern Region Underwriting',
                                'id': 'pc:SDrypgK62o6oS1TxOGcvF',
                                'type': 'Group',
                                'uri': '/admin/v1/groups/pc:SDrypgK62o6oS1TxOGcvF'
                            },
                            {
                                'displayName': 'Los Angeles Branch UW',
                                'id': 'pc:SJxAbEha2jYpG9Mb5_KAo',
                                'type': 'Group',
                                'uri': '/admin/v1/groups/pc:SJxAbEha2jYpG9Mb5_KAo'
                            }
                        ],
                        'id': 'pc:Si6MBM-35EAhneDubeFsl',
                        'lastName': 'Applegate',
                        'organization': {
                            'displayName': 'Enigma Fire & Casualty',
                            'id': 'systemTables:1',
                            'type': 'Organization',
                            'uri': '/admin/v1/organizations/systemTables:1'
                        },
                        'roles': [
                            {
                                'displayName': 'Reinsurance Manager',
                                'id': 'reinsurance_manager',
                                'type': 'Role',
                                'uri': '/admin/v1/roles/reinsurance_manager'
                            },
                            {
                                'displayName': 'Underwriter',
                                'id': 'underwriter',
                                'type': 'Role',
                                'uri': '/admin/v1/roles/underwriter'
                            }
                        ],
                        'useOrgAddress': True,
                        'useProducerCodeSecurity': False,
                        'userType': {
                            'code': 'underwriter',
                            'name': 'Underwriter'
                        },
                        'username': 'aapplegate',
                        'uwAuthorityProfiles': [
                            {
                                'displayName': 'Underwriter 1',
                                'id': 'pc:underwriter1',
                                'type': 'UWAuthorityProfile',
                                'uri': '/admin/v1/uw-authority-profiles/pc:underwriter1'
                            }
                        ],
                        'vacationStatus': {
                            'code': 'atwork',
                            'name': 'At work'
                        },
                        'workPhone': {
                            'displayName': '213-555-8164',
                            'number': '2135558164'
                        }
                    },
                    'checksum': 'ec4710cd2af59bdc1cd7e15a18707d84',
                    'links': {
                        'self': {'href': '/admin/v1/users/pc:Si6MBM-35EAhneDubeFsl', 'methods': ['delete', 'get', 'patch']}
                    }
                },
                ...
            ],
            'links': {
                'first': {'href': '/admin/v1/users?fields=%2Adefault&pageSize=20', 'methods': ['get']},
                'next': {'href': '/admin/v1/users?fields=%2Adefault&pageSize=20&pageOffset=20', 'methods': ['get']},
                'self': {'href': '/admin/v1/users?fields=%2Adefault&pageSize=20', 'methods': ['get']}
            }
        }

        """

        if not next_page_url:
            request_url = self.config()["adminUrl"] + "/users"

            encoded_query = self.process_parameters(fields=fields, filters=filters, page_size=page_size)
            if encoded_query:
                request_url += "?" + encoded_query
        else:
            request_url = self.config()["restUrl"] + next_page_url

        return self.do_request(method="GET", url=request_url)

    # end method definition

    def get_users_iterator(self, fields: list | None = None, filters: list | None = None, page_size: int = 25) -> iter:
        """Get an iterator object that can be used to traverse all Guidewire users.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of users.

        Example usage:
            users = guidewire_object.get_users_iterator()
            for user in users:
                logger.info("Traversing Guidewire user -> '%s'...", user.get("attributes", {}).get("displayName"))

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - active
                - displayName
                - externalUser
                - firstName
                - id
                - lastName
                - organization
                - useOrgAddress
                - useProducerCodeSecurity
                - username
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the value to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of groups to return.
            next_page_url (str, optional):
                The Guidewire URL to retrieve the next page of Guidewire groups (pagination).
                This is used for the iterator get_groups_iterator() below.

        Returns:
            iter:
                A generator yielding one Guidewire user per iteration.
                If the REST API fails, returns no value.

        """

        next_page_url = None

        while True:
            response = self.get_users(fields=fields, filters=filters, page_size=page_size, next_page_url=next_page_url)
            if not response or "data" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["data"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_url = response.get("links", {}).get("next", {}).get("href")
            if not next_page_url:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def get_user(self, user_id: str) -> dict:
        """Retrieve details of a specific user.

        Args:
            user_id (str):
                The unique identifier of the group.

        Returns:
            dict:
                JSON response containing group details.

        Example response;
        {
            'data': {
                'attributes': {
                    'active': True,
                    'displayName': 'Alice Applegate',
                    'externalUser': False,
                    'firstName': 'Alice',
                    'groups': [{...}, {...}],
                    'id': 'pc:Si6MBM-35EAhneDubeFsl',
                    'lastName': 'Applegate',
                    'organization': {
                        'displayName': 'Enigma Fire & Casualty',
                        'id': 'systemTables:1',
                        'type': 'Organization',
                        'uri': '/admin/v1/organizations/systemTables:1'
                    },
                    'roles': [{...}, {...}],
                    'useOrgAddress': True,
                    'useProducerCodeSecurity': False,
                    'userType': {
                        'code': 'underwriter',
                        'name': 'Underwriter'
                    },
                    'username': 'aapplegate',
                    'uwAuthorityProfiles': [{...}],
                    'vacationStatus': {
                        'code': 'atwork',
                        'name': 'At work'
                    },
                    'workPhone': {
                        'displayName': '213-555-8164',
                        'number': '2135558164'
                    }
                },
                'checksum': 'ec4710cd2af59bdc1cd7e15a18707d84',
                'links': {
                    'producer-codes': {
                        'href': '/admin/v1/users/pc:Si6MBM-35EAhneDubeFsl/producer-codes',
                        'methods': [...]
                    },
                    'self': {
                        'href': '/admin/v1/users/pc:Si6MBM-35EAhneDubeFsl',
                        'methods': [...]
                    }
                }
            }
        }

        """

        request_url = self.config()["adminUrl"] + "/users/" + str(user_id)

        return self.do_request(method="GET", url=request_url)

    # end method definition

    def update_user(self, user_id: str, user_data: dict) -> dict:
        """Update an existing user.

        Args:
            user_id (str):
                The unique identifier of the user.
            user_data (dict):
                Dictionary containing updated user information.

        Returns:
            dict:
                Response with updated user details.

        """

        request_url = self.config()["adminUrl"] + "/users/" + str(user_id)

        return self.do_request(method="PUT", url=request_url, data=user_data)

    # end method definition

    def get_accounts(
        self,
        fields: list | None = None,
        filters: list | None = None,
        page_size: int = 25,
        next_page_url: str | None = None,
    ) -> dict | None:
        """Retrieve a list of accounts.

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - accountNumber
                - accountHolder
                - accountStatus
                - businessOperationsDescription
                - createdDate
                - frozen
                - id
                - industryCode
                - organizationType
                - preferredCoverageCurrency
                - preferredSettlementCurrency
                - primaryLanguage
                - primaryLocale
                - primaryLocation
                - producerCodes
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the filue to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of groups to return.
            next_page_url (str, optional):
                The Guidewire URL to retrieve the next page of Guidewire groups (pagination).
                This is used for the iterator get_groups_iterator() below.

        Returns:
            dict:
                JSON response containing account data. None in case of an error.

        """

        if not next_page_url:
            request_url = self.config()["accountUrl"] + "/accounts"

            encoded_query = self.process_parameters(fields=fields, filters=filters, page_size=page_size)
            if encoded_query:
                request_url += "?" + encoded_query
        else:
            request_url = self.config()["restUrl"] + next_page_url

        return self.do_request(method="GET", url=request_url)

    # end method definition

    def get_accounts_iterator(
        self, fields: list | None = None, filters: list | None = None, page_size: int = 25
    ) -> iter:
        """Get an iterator object that can be used to traverse all Guidewire accounts.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of groups.

        Example usage:
            accounts = guidewire_object.get_accounts_iterator()
            for account in accounts:
                logger.info("Traversing Guidewire account -> '%s'...", account.get("attributes", {}).get("displayName"))

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - accountNumber
                - accountHolder
                - accountStatus
                - businessOperationsDescription
                - createdDate
                - frozen
                - id
                - industryCode
                - organizationType
                - preferredCoverageCurrency
                - preferredSettlementCurrency
                - primaryLanguage
                - primaryLocale
                - primaryLocation
                - producerCodes
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the filue to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of accounts to return.

        Returns:
            iter:
                A generator yielding one Guidewire account per iteration.
                If the REST API fails, returns no value.

        """

        next_page_url = None

        while True:
            response = self.get_accounts(
                fields=fields, filters=filters, page_size=page_size, next_page_url=next_page_url
            )
            if not response or "data" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["data"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_url = response.get("links", {}).get("next", {}).get("href")
            if not next_page_url:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def get_account(self, account_id: str) -> dict:
        """Retrieve details of a specific account.

        Args:
            account_id:
                The unique identifier of the account.

        Returns:
            dict:
                JSON response containing account details.

        """

        request_url = self.config()["accountUrl"] + "/accounts/" + str(account_id)

        return self.do_request(method="GET", url=request_url)

    # end method definition

    def search_account(self, attributes: dict) -> dict:
        """Search accounts based on its attributes.

        Args:
            attributes (dict):
                The attribute to search the value in. Possible key values:
                * "accountNumber"
                * "addressLine1"
                * "addressLine2"
                * "city"
                * "country"
                * "companyName"

        Returns:
            dict:
                JSON response containing account details.

        Example:
        {
            'count': 2,
            'data': [
                {
                    'attributes': {
                        'accountHolder': {
                            'displayName': 'Armstrong and Company',
                            'id': 'test_pc:1',
                            'type': 'AccountContact',
                            'uri': '/account/v1/accounts/pc:ds:1/contacts/test_pc:1'
                        },
                        'accountNumber': 'C000212105',
                        'accountStatus': {...},
                        'businessOperationsDescription': 'business description',
                        'createdDate': '2025-07-14T03:59:30.055Z',
                        'frozen': False,
                        'id': 'pc:ds:1',
                        'industryCode': {...},
                        'numberOfContacts': '8',
                        'organizationType': {...},
                        'preferredCoverageCurrency': {...},
                        'preferredSettlementCurrency': {...},
                        'primaryLanguage': {...},
                        'primaryLocale': {...},
                        'primaryLocation': {...},
                        'producerCodes': [...]
                    },
                    'checksum': '2',
                    'links': {
                        'do-not-destroy': {...},
                        'freeze': {...},
                        'merge': {...},
                        'move-policies': {...},
                        'move-submissions': {...},
                        'self': {...}
                    }
                },
                {...}
            ],
            'links': {
                'first': {...},
                'self': {...}
            }
        }

        """

        body = {"data": {"attributes": attributes}}

        request_url = self.config()["accountSearchUrl"]

        return self.do_request(method="POST", json_data=body, url=request_url)

    # end method definition

    def add_account(self, account_data: dict) -> dict:
        """Create a new account.

        Args:
            account_data:
                Dictionary containing account information.

        Returns:
            dict:
                JSON response with created account details.

        """

        request_url = self.config()["accountUrl"] + "/accounts"

        return self.do_request(method="POST", url=request_url, data=account_data)

    # end method definition

    def update_account(self, account_id: str, account_data: dict) -> dict:
        """Update an existing account.

        Args:
            account_id:
                The unique identifier of the account.
            account_data:
                Dictionary containing updated account information.

        Returns:
            dict:
                JSON response with updated account details.

        """

        request_url = self.config()["accountUrl"] + "/accounts/" + str(account_id)

        return self.do_request(method="PUT", url=request_url, data=account_data)

    # end method definition

    def delete_account(self, account_id: str) -> dict:
        """Delete an account.

        Args:
            account_id (str):
                The unique identifier of the account to delete.

        Returns:
            dict:
                JSON response indicating deletion success.

        """

        request_url = self.config()["accountUrl"] + "/accounts/" + str(account_id)

        return self.do_request(method="DELETE", url=request_url)

    # end method definition

    def get_policies(
        self,
        fields: list | None = None,
        filters: list | None = None,
        page_size: int = 25,
        next_page_url: str | None = None,
    ) -> dict | None:
        """Retrieve a list of policies.

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - displayName
                - groupType
                - id
                - loadFactor
                - name
                - organization
                - parent
                - securityZone
                - supervisor
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the value to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of groups to return.
            next_page_url (str, optional):
                The Guidewire URL to retrieve the next page of Guidewire groups (pagination).
                This is used for the iterator get_groups_iterator() below.

        Returns:
            dict | None:
                JSON response containing claim data.

        """

        if not next_page_url:
            request_url = self.config()["policyUrl"] + "/policies"

            encoded_query = self.process_parameters(fields=fields, filters=filters, page_size=page_size)
            if encoded_query:
                request_url += "?" + encoded_query
        else:
            request_url = self.config()["restUrl"] + next_page_url

        return self.do_request(method="GET", url=request_url)

    # end method definition

    def get_policies_iterator(
        self, fields: list | None = None, filters: list | None = None, page_size: int = 25
    ) -> iter:
        """Get an iterator object that can be used to traverse all Guidewire policies.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of groups.

        Example usage:
            policies = guidewire_object.get_policies_iterator()
            for policy in policies:
                logger.info("Traversing Guidewire policy -> '%s'...", policy.get("attributes", {}).get("displayName"))

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - displayName
                - groupType
                - id
                - loadFactor
                - name
                - organization
                - parent
                - securityZone
                - supervisor
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the value to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of policies to return.

        Returns:
            iter:
                A generator yielding one Guidewire account per iteration.
                If the REST API fails, returns no value.

        """

        next_page_url = None

        while True:
            response = self.get_policies(
                fields=fields, filters=filters, page_size=page_size, next_page_url=next_page_url
            )
            if not response or "data" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["data"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_url = response.get("links", {}).get("next", {}).get("href")
            if not next_page_url:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def search_policy(self, attributes: dict) -> dict:
        """Search a specific policy based on its attributes.

        See: https://docs.guidewire.com/cloud/pc/202407/apiref/generated/Policy%20API/search-policies--post

        Args:
            attributes (dict):
                The attribute to search the value in. Possible key values:
                * "policyNumber" (str)
                * "city" (str)
                * "state" (dict with keys "code", "name"), e.g. {"code": "GA", "name": "Georgia"}
                * "country" (str)
                * "postalCode" (str)
                * "street" (str)
                * "companyName" (str)
                * "firstName" (str)
                * "lastName" (str)
                * "officialId" (str)

        Returns:
            dict:
                JSON response containing account details.

        Example:
        {
            'count': 1,
            'data': [
                {
                    'attributes': {
                        'accountNumber': 'C000212105',
                        'effectiveDate': '2025-07-14T04:01:00.000Z',
                        'expirationDate': '2026-07-14T04:01:00.000Z',
                        'insuredName': 'Armstrong and Company',
                        'policyAddress': '142 Central Ave, Metter, GA 30439',
                        'policyId': 'pc:Sn09Itxh7Btpc8izhUrtc',
                        'policyNumber': '5050680845',
                        'producerOfRecordName': 'Armstrong and Company',
                        'producerOfServiceName': 'Armstrong and Company',
                        'product': {
                            'displayName': 'Manual Products',
                            'id': 'Manual'
                        }
                    },
                    'links': {...}
                }
            ],
            'links': {
                'first': {'href': '/policy/v1/search/policies', 'methods': ['post']},
                'self': {'href': '/policy/v1/search/policies', 'methods': ['post']}
            }
        }

        """

        body = {"data": {"attributes": attributes}}

        request_url = self.config()["policySearchUrl"]

        return self.do_request(method="POST", json_data=body, url=request_url)

    # end method definition

    def get_claims(
        self,
        fields: list | None = None,
        filters: list | None = None,
        page_size: int = 25,
        next_page_url: str | None = None,
    ) -> dict | None:
        """Retrieve a list of claims.

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - displayName
                - groupType
                - id
                - loadFactor
                - name
                - organization
                - parent
                - securityZone
                - supervisor
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the value to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of groups to return.
            next_page_url (str, optional):
                The Guidewire URL to retrieve the next page of Guidewire groups (pagination).
                This is used for the iterator get_groups_iterator() below.

        Returns:
            dict | None:
                JSON response containing claim data.

        """

        if not next_page_url:
            request_url = self.config()["claimUrl"] + "/claim-infos"

            encoded_query = self.process_parameters(fields=fields, filters=filters, page_size=page_size)
            if encoded_query:
                request_url += "?" + encoded_query
        else:
            request_url = self.config()["restUrl"] + next_page_url

        return self.do_request(method="GET", url=request_url)

    # end method definition

    def get_claims_iterator(self, fields: list | None = None, filters: list | None = None, page_size: int = 25) -> iter:
        """Get an iterator object that can be used to traverse all Guidewire claims.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of groups.

        Example usage:
            claims = guidewire_object.get_claims_iterator()
            for claim in claims:
                logger.info("Traversing Guidewire claim -> '%s'...", claim.get("attributes", {}).get("displayName"))

        Args:
            fields (list | None, optional):
                The list of fields in the results. If None, all default
                fields are returned.
                Fields for Guidewire accounts:
                - *all = return all fields
                - *default = return just the default list of fields
                - *summary = return the fields defined for giving a summary
                - *detail = details
                - displayName
                - groupType
                - id
                - loadFactor
                - name
                - organization
                - parent
                - securityZone
                - supervisor
            filters (list | None, optional):
                List of dictionaries with three keys each:
                - "attribute" - name of the attribute to use for the filter (available attributes see above)
                - "op" - operator:
                    * eq - equal
                    * ne - not equal
                    * lt - less than - also usable for dates (before)
                    * gt - greater than - also usable for dates (after)
                    * le - less or equal
                    * ge - greater or equal
                    * in - is in list
                    * ni - is NOT in list
                    * sw - starts with
                    * cn - contains
                - "value": the value to filter for. Either literal or list of values
            page_size (int, optional):
                The maximum number of groups to return.

        Returns:
            iter:
                A generator yielding one Guidewire claim per iteration.
                If the REST API fails, returns no value.

        """

        next_page_url = None

        while True:
            response = self.get_claims(fields=fields, filters=filters, page_size=page_size, next_page_url=next_page_url)
            if not response or "data" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["data"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_url = response.get("links", {}).get("next", {}).get("href")
            if not next_page_url:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def get_claim(self, claim_id: str) -> dict:
        """Retrieve details of a specific claim.

        Args:
            claim_id (str):
                The unique identifier of the claim.

        Returns:
            dict:
                JSON response containing claim details.

        """

        request_url = self.config()["claimUrl"] + "/claims/" + str(claim_id)

        return self.do_request(method="GET", url=request_url)

    # end method definition

    def search_claim(self, attributes: dict) -> dict:
        """Search a specific claim based on its attributes.

        Args:
            attributes (dict):
                The attribute to search the value in. Possible key values:
                * TBD

        Returns:
            dict:
                JSON response containing account details.

        """

        body = {"data": {"attributes": attributes}}

        request_url = self.config()["claimSearchUrl"]

        return self.do_request(method="POST", json_data=body, url=request_url)

    # end method definition

    def add_claim(self, claim_data: dict) -> dict:
        """Create a new claim.

        Args:
            claim_data (dict):
                Dictionary containing claim information.

        Returns:
            dict:
                JSON response with created claim details.

        """

        request_url = self.config()["claimUrl"] + "/claims"

        return self.do_request(method="POST", url=request_url, data=claim_data)

    # end method definition

    def update_claim(self, claim_id: str, claim_data: dict) -> dict:
        """Update an existing claim.

        Args:
            claim_id (str):
                The unique identifier of the claim.
            claim_data (dict):
                Dictionary containing updated claim information.

        Returns:
            dict:
                Response with updated claim details.

        """

        request_url = self.config()["claimUrl"] + "/claims/" + str(claim_id)

        return self.do_request(method="PUT", url=request_url, data=claim_data)

    # end method definition

    def delete_claim(self, claim_id: str) -> dict:
        """Delete a claim.

        Args:
            claim_id (str):
                The unique identifier of the claim to delete.

        Returns:
            dict:
                Response indicating deletion success.

        """

        request_url = self.config()["claimUrl"] + "/claims/" + str(claim_id)

        return self.do_request(method="DELETE", url=request_url)

    # end method definition

"""
Salesforce Module to interact with the Salesforce API
See: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_rest.htm

Class: Salesforce
Methods:

__init__ : class initializer
config : Returns config data set
credentials: Returns the token data

request_header: Returns the request header for Salesforce API calls
do_request: Call an Salesforce REST API in a safe way
parse_request_response: Parse the REST API responses and convert
                        them to Python dict in a safe way
exist_result_item: Check if an dict item is in the response
                   of the Salesforce API call
get_result_value: Check if a defined value (based on a key) is in the Salesforce API response

authenticate: Authenticates at Salesforce API

get_object_id_by_name: Get the ID of a given Salesforce object with a given type and name
get_object: Get a Salesforce object based on a defined
            field value and return selected result fields.
add_object: Add object to Salesforce. This is a generic wrapper method
            for the actual add methods.

get_group: Get a Salesforce group based on its ID.
add_group: Add a new Salesforce group.
update_group: Update a Salesforce group.
get_group_members: Get Salesforce group members
add_group_member: Add a user or group to a Salesforce group

get_all_user_profiles: Get all user profiles
get_user_profile_id: Get a user profile ID by profile name
get_user_id: Get a user ID by user name
get_user: Get a Salesforce user based on its ID.
add_user: Add a new Salesforce user.
update_user: Update a Salesforce user.
update_user_password: Update the password of a Salesforce user.
update_user_photo: update the Salesforce user photo.

add_account: Add a new Account object to Salesforce.
add_product: Add a new Product object to Salesforce.
add_opportunity: Add a new Opportunity object to Salesfoce.
add_case: Add a new Case object to Salesforce. The case number
          is automatically created and can not be provided.
add_asset: Add a new Asset object to Salesforce.
add_contract: Add a new Contract object to Salesforce.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import os
import json
import logging
import time

from typing import Optional, Union, Any

from http import HTTPStatus
import requests

logger = logging.getLogger("pyxecm.customizer.salesforce")

REQUEST_LOGIN_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
}

REQUEST_TIMEOUT = 60
REQUEST_RETRY_DELAY = 20
REQUEST_MAX_RETRIES = 3

SALESFORCE_API_VERSION = "v60.0"

class Salesforce(object):
    """Used to retrieve and automate stettings in Salesforce."""

    _config: dict
    _access_token = None
    _instance_url = None

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        authorization_url: str = "",
        security_token: str = "",
    ):
        """Initialize the Salesforce object

        Args:
            base_url (str): base URL of the Salesforce tenant
            authorization_url (str): authorization URL of the Salesforce tenant, typically ending with "/services/oauth2/token"
            client_id (str): Salesforce Client ID
            client_secret (str): Salesforce Client Secret
            username (str): user name in Saleforce
            password (str): password of the user
            authorization_url (str, optional): URL for Salesforce login. If not given it will be constructed with default values
                                               using base_url
            security_token (str, optional): security token for Salesforce login
        """

        # The instance URL is also returned by the authenticate call
        # but typically it is identical to the base_url.
        self._instance_url = base_url

        salesforce_config = {}

        # Store the credentials and parameters in a config dictionary:
        salesforce_config["clientId"] = client_id
        salesforce_config["clientSecret"] = client_secret
        salesforce_config["username"] = username
        salesforce_config["password"] = password
        salesforce_config["securityToken"] = security_token

        # Set the Salesforce URLs and REST API endpoints:
        salesforce_config["baseUrl"] = base_url
        salesforce_config["objectUrl"] = salesforce_config[
            "baseUrl"
        ] + "/services/data/{}/sobjects/".format(SALESFORCE_API_VERSION)
        salesforce_config["queryUrl"] = salesforce_config[
            "baseUrl"
        ] + "/services/data/{}/query/".format(SALESFORCE_API_VERSION)
        salesforce_config["compositeUrl"] = salesforce_config[
            "baseUrl"
        ] + "/services/data/{}/composite/".format(SALESFORCE_API_VERSION)
        salesforce_config["connectUrl"] = salesforce_config[
            "baseUrl"
        ] + "/services/data/{}/connect/".format(SALESFORCE_API_VERSION)
        salesforce_config["toolingUrl"] = salesforce_config[
            "baseUrl"
        ] + "/services/data/{}/tooling/".format(SALESFORCE_API_VERSION)
        if authorization_url:
            salesforce_config["authenticationUrl"] = authorization_url
        else:
            salesforce_config["authenticationUrl"] = (
                salesforce_config["baseUrl"] + "/services/oauth2/token"
            )
        # URLs that are based on the objectURL (sobjects/):
        salesforce_config["userUrl"] = salesforce_config["objectUrl"] + "User/"
        salesforce_config["groupUrl"] = salesforce_config["objectUrl"] + "Group/"
        salesforce_config["groupMemberUrl"] = (
            salesforce_config["objectUrl"] + "GroupMember/"
        )
        salesforce_config["accountUrl"] = salesforce_config["objectUrl"] + "Account/"
        salesforce_config["productUrl"] = salesforce_config["objectUrl"] + "Product2/"
        salesforce_config["opportunityUrl"] = (
            salesforce_config["objectUrl"] + "Opportunity/"
        )
        salesforce_config["caseUrl"] = salesforce_config["objectUrl"] + "Case/"
        salesforce_config["assetUrl"] = salesforce_config["objectUrl"] + "Asset/"
        salesforce_config["contractUrl"] = salesforce_config["objectUrl"] + "Contract/"

        # Set the data for the token request
        salesforce_config["authenticationData"] = {
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "username": username,
            "password": password,
        }

        self._config = salesforce_config

    # end method definition

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    # end method definition

    def credentials(self) -> dict:
        """Return the login credentials

        Returns:
            dict: dictionary with login credentials for Salesforce
        """
        return self.config()["authenticationData"]

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
        }
        if content_type:
            request_header["Content-Type"] = content_type

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
        params: dict | None = None,
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
        verify: bool = True,
    ) -> dict | None:
        """Call an Salesforce REST API in a safe way

        Args:
            url (str): URL to send the request to.
            method (str, optional): HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional): Request Headers. Defaults to None.
            data (dict | None, optional): Request payload. Defaults to None
            files (dict | None, optional): Dictionary of {"name": file-tuple} for multipart encoding upload.
                                           file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            params (dict | None, optional): Add key-value pairs to the query string of the URL.
                                            When you use the params parameter, requests automatically appends
                                            the key-value pairs to the URL as part of the query string
            timeout (int | None, optional): Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional): Whether or not an error should be logged in case of a failed REST call.
                                         If False, then only a warning is logged. Defaults to True.
            warning_message (str, optional): Specific warning message. Defaults to "". If not given the error_message will be used.
            failure_message (str, optional): Specific error message. Defaults to "".
            success_message (str, optional): Specific success message. Defaults to "".
            max_retries (int, optional): How many retries on Connection errors? Default is REQUEST_MAX_RETRIES.
            retry_forever (bool, optional): Eventually wait forever - without timeout. Defaults to False.
            parse_request_response (bool, optional): should the response.text be interpreted as json and loaded into a dictionary. True is the default.
            stream (bool, optional): parameter is used to control whether the response content should be immediately downloaded or streamed incrementally
            verify (bool, optional): specify whether or not SSL certificates should be verified when making an HTTPS request. Default = True

        Returns:
            dict | None: Response of OTDS REST API or None in case of an error.
        """

        if headers is None:
            logger.error("Missing request header. Cannot send request to Core Share!")
            return None

        # In case of an expired session we reauthenticate and
        # try 1 more time. Session expiration should not happen
        # twice in a row:
        retries = 0

        while True:
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    data=data,
                    json=json_data,
                    files=files,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                    stream=stream,
                    verify=verify,
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
                    logger.debug("Session has expired - try to re-authenticate...")
                    self.authenticate(revalidate=True)
                    # Make sure to not change an existing content type
                    # the do_request() method is called with:
                    headers = self.request_header(
                        content_type=headers.get("Content-Type", None)
                    )
                    retries += 1
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
                            "%s; status -> %s/%s; warning -> %s",
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
                "Retrying REST API %s call -> %s... (retry = %s)",
                method,
                url,
                str(retries),
            )
        # end while True

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

    def exist_result_item(self, response: dict, key: str, value: str) -> bool:
        """Check existence of key / value pair in the response properties of an Salesforce API call.

        Args:
            response (dict): REST response from an Salesforce API call
            key (str): property name (key)
            value (str): value to find in the item with the matching key
        Returns:
            bool: True if the value was found, False otherwise
        """

        if not response:
            return False

        if "records" in response:
            records = response["records"]
            if not records or not isinstance(records, list):
                return False

            for record in records:
                if value == record[key]:
                    return True
        else:
            if not key in response:
                return False
            if value == response[key]:
                return True

        return False

    # end method definition

    def get_result_value(
        self,
        response: dict,
        key: str,
        index: int = 0,
    ) -> str | None:
        """Get value of a result property with a given key of an Salesforce API call.

        Args:
            response (dict): REST response from an Salesforce REST Call
            key (str): property name (key)
            index (int, optional): Index to use (1st element has index 0).
                                   Defaults to 0.
        Returns:
            str: value for the key, None otherwise
        """

        if not response:
            return None

        # do we have a complex response - e.g. from an SOQL query?
        # these have list of "records":
        if "records" in response:
            values = response["records"]
            if not values or not isinstance(values, list) or len(values) - 1 < index:
                return None
            value = values[index][key]
        else:  # simple response - try to find key in response directly:
            if not key in response:
                return None
            value = response[key]

        return value

    # end method definition

    def authenticate(self, revalidate: bool = False) -> str | None:
        """Authenticate at Salesforce with client ID and client secret.

        Args:
            revalidate (bool, optional): determinse if a re-athentication is enforced
                                         (e.g. if session has timed out with 401 error)
        Returns:
            str: Access token. Also stores access token in self._access_token. None in case of error
        """

        # Already authenticated and session still valid?
        if self._access_token and not revalidate:
            logger.debug(
                "Session still valid - return existing access token -> %s",
                str(self._access_token),
            )
            return self._access_token

        request_url = self.config()["authenticationUrl"]
        request_header = REQUEST_LOGIN_HEADERS

        logger.debug("Requesting Salesforce Access Token from -> %s", request_url)

        authenticate_post_body = self.credentials()

        response = None
        self._access_token = None
        self._instance_url = None

        try:
            response = requests.post(
                request_url,
                data=authenticate_post_body,
                headers=request_header,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.ConnectionError as exception:
            logger.warning(
                "Unable to connect to -> %s : %s",
                self.config()["authenticationUrl"],
                exception,
            )
            return None

        if response.ok:
            authenticate_dict = self.parse_request_response(response)
            if not authenticate_dict:
                return None
            else:
                # Store authentication access_token:
                self._access_token = authenticate_dict["access_token"]
                logger.debug("Access Token -> %s", self._access_token)
                self._instance_url = authenticate_dict["instance_url"]
                logger.debug("Instance URL -> %s", self._instance_url)
        else:
            logger.error(
                "Failed to request an Salesforce Access Token; error -> %s",
                response.text,
            )
            return None

        return self._access_token

    # end method definition

    def get_object_id_by_name(
        self, object_type: str, name: str, name_field: str = "Name"
    ) -> Optional[str]:
        """Get the ID of a given Salesforce object with a given type and name.

        Args:
            object_type (str): Sales object type, like "Account", "Case", ...
            name (str): Name of the Salesforce object.
            name_field (str, optional): Field where the name is stored. Defaults to "Name".

        Returns:
            Optional[str]: Object ID or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["queryUrl"]

        query = f"SELECT Id FROM {object_type} WHERE {name_field} = '{name}'"

        response = self.do_request(
            method="GET",
            url=request_url,
            headers=request_header,
            params={"q": query},
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Salesforce object ID for object type -> '{}' and object name -> '{}'".format(
                object_type, name
            ),
        )
        if not response:
            return None

        return self.get_result_value(response, "Id")

    # end method definition

    def get_object(
        self,
        object_type: str,
        search_field: str,
        search_value: str,
        result_fields: list | None,
        limit: int = 200,
    ) -> dict | None:
        """Get a Salesforce object based on a defined field value and return selected result fields.

        Args:
            object_type (str): Salesforce Business Object type. Such as "Account" or "Case".
            search_field (str): object field to search in
            search_value (str): value to search for
            result_fields (list | None): list of fields to return. If None, then all standard fields
                                         of the object will be returned.
            limit (int, optional): maximum number of fields to return. Salesforce enforces 200 as upper limit.

        Returns:
            dict | None: Dictionary with the Salesforce object data.

            Example response:
            {
                'totalSize': 2,
                'done': True,
                'records': [
                    {
                        'attributes': {
                            'type': 'Opportunity',
                            'url': '/services/data/v60.0/sobjects/Opportunity/006Dn00000EclybIAB'
                        },
                        'Id': '006Dn00000EclybIAB'
                    },
                    {
                        'attributes': {
                            'type': 'Opportunity',
                            'url': '/services/data/v60.0/sobjects/Opportunity/006Dn00000EclyfIAB'
                        },
                        'Id': '006Dn00000EclyfIAB'
                    }
                ]
            }
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        if search_field and not search_value:
            logger.error(
                "No search value has been provided for search field -> %s!",
                search_field,
            )
            return None
        if not result_fields:
            logger.debug(
                "No result fields defined. Using 'FIELDS(STANDARD)' to deliver all standard fields of the object."
            )
            result_fields = ["FIELDS(STANDARD)"]

        query = "SELECT {} FROM {}".format(", ".join(result_fields), object_type)
        if search_field and search_value:
            query += " WHERE {}='{}'".format(search_field, search_value)
        query += " LIMIT {}".format(str(limit))

        request_header = self.request_header()
        request_url = self.config()["queryUrl"] + "?q={}".format(query)

        logger.debug(
            "Sending query -> %s to Salesforce; calling -> %s", query, request_url
        )

        return self.do_request(
            method="GET",
            url=request_url,
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to retrieve Salesforce object type -> '{}' with {} = {}".format(
                object_type, search_field, search_value
            ),
        )

    # end method definition

    def add_object(self, object_type: str, **kwargs: Any) -> dict | None:
        """Add object to Salesforce. This is a generic wrapper method
           for the actual add methods.

        Args:
            object_type (str): Type of the Salesforce business object, like "Account" or "Case".
            **kwargs (dict): keyword / value ictionary with additional parameters

        Returns:
            dict | None: Dictionary with the Salesforce object data or None if the request fails.
        """

        match object_type:
            case "Account":
                return self.add_account(
                    account_name=kwargs.pop("AccountName", None),
                    account_number=kwargs.pop("AccountNumber", None),
                    account_type=kwargs.pop("Type", None),
                    description=kwargs.pop("Description", None),
                    industry=kwargs.pop("Industry", None),
                    website=kwargs.pop("Website", None),
                    phone=kwargs.pop("Phone", None),
                    **kwargs,
                )
            case "Product":
                return self.add_product(
                    product_name=kwargs.pop("Name", None),
                    product_code=kwargs.pop("ProductCode", None),
                    description=kwargs.pop("Description", None),
                    price=kwargs.pop("Price", None),
                    **kwargs,
                )
            case "Opportunity":
                return self.add_opportunity(
                    name=kwargs.pop("Name", None),
                    stage=kwargs.pop("StageName", None),
                    close_date=kwargs.pop("CloseDate", None),
                    amount=kwargs.pop("Amount", None),
                    account_id=kwargs.pop("AccountId", None),
                    description=kwargs.pop("Description", None),
                    **kwargs,
                )
            case "Case":
                return self.add_case(
                    subject=kwargs.pop("Subject", None),
                    description=kwargs.pop("Description", None),
                    status=kwargs.pop("Status", None),
                    priority=kwargs.pop("Priority", None),
                    origin=kwargs.pop("Origin", None),
                    account_id=kwargs.pop("AccountId", None),
                    owner_id=kwargs.pop("OwnerId", None),
                    asset_id=kwargs.pop("AssetId", None),
                    product_id=kwargs.pop("ProductId", None),
                    **kwargs,
                )
            case "Contract":
                return self.add_contract(
                    account_id=kwargs.pop("AccountId", None),
                    start_date=kwargs.pop("ContractStartDate", None),
                    contract_term=kwargs.pop("ContractTerm", None),
                    status=kwargs.pop("Status", None),
                    description=kwargs.pop("Description", None),
                    contract_type=kwargs.pop("ContractType", None),
                    **kwargs,
                )
            case "Asset":
                return self.add_asset(
                    asset_name=kwargs.pop("Name", None),
                    product_id=kwargs.pop("Product", None),
                    serial_number=kwargs.pop("SerialNumber", None),
                    status=kwargs.pop("Status", None),
                    purchase_date=kwargs.pop("PurchaseDate", None),
                    install_date=kwargs.pop("InstallDate", None),
                    description=kwargs.pop("AssetDescription", None),
                    **kwargs,
                )
            case _:
                logger.error(
                    "Unsupported Salesforce business object -> %s!",
                    object_type,
                )

    # end method definition

    def get_group_id(self, groupname: str) -> Optional[str]:
        """Get a group ID by group name.

        Args:
            groupname (str): Name of the Group.

        Returns:
            Optional[str]: Technical ID of the group
        """

        return self.get_object_id_by_name(
            object_type="Group", name=groupname, name_field="Name"
        )

    # end method definition

    def get_group(self, group_id: str) -> dict | None:
        """Get a Salesforce group based on its ID.

        Args:
            group_id (str): ID of the Salesforce group

        Returns:
            dict | None: Dictionary with the Salesforce group data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["groupUrl"] + group_id

        logger.debug(
            "Get Salesforce group with ID -> %s; calling -> %s", group_id, request_url
        )

        return self.do_request(
            method="GET",
            url=request_url,
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Salesforce group with ID -> {}".format(
                group_id
            ),
        )

    # end method definition

    def add_group(
        self,
        group_name: str,
        group_type: str = "Regular",
    ) -> dict | None:
        """Add a new Salesforce group.

        Args:
            group_name (str): Name of the new Salesforce group

        Returns:
            dict | None: Dictionary with the Salesforce Group data or None if the request fails.

            Example response:
            {
                'id': '00GDn000000KWE0MAO',
                'success': True,
                'errors': []
            }
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["groupUrl"]

        payload = {"Name": group_name, "Type": group_type}

        logger.debug(
            "Adding Salesforce group -> %s; calling -> %s", group_name, request_url
        )

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Salesforce group -> '{}'".format(group_name),
        )

    # end method definition

    def update_group(
        self,
        group_id: str,
        update_data: dict,
    ) -> dict | None:
        """Update a Salesforce group.

        Args:
            group_id (str): The Salesforce group ID.
            update_data (dict): Dictionary containing the fields to update.

        Returns:
            dict: Response from the Salesforce API.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()

        request_url = self.config()["groupUrl"] + group_id

        logger.debug(
            "Update Salesforce group with ID -> %s; calling -> %s",
            group_id,
            request_url,
        )

        return self.do_request(
            method="PATCH",
            url=request_url,
            headers=request_header,
            json_data=update_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update Salesforce group with ID -> {}".format(
                group_id
            ),
        )

    # end method definition

    def get_group_members(self, group_id: str) -> list | None:
        """Get Salesforce group members

        Args:
            group_id (str): Id of the group to retrieve the members

        Returns:
            list | None: result

            Example response:
            {
                'totalSize': 1,
                'done': True,
                'records': [
                    {
                        'attributes': {
                            'type': 'GroupMember',
                            'url': '/services/data/v60.0/sobjects/GroupMember/011Dn000000ELhwIAG'
                        },
                        'UserOrGroupId': '00GDn000000KWE5MAO'
                    }
                ]
            }
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()

        request_url = self.config()["queryUrl"]

        query = f"SELECT UserOrGroupId FROM GroupMember WHERE GroupId = '{group_id}'"
        params = {"q": query}

        logger.debug(
            "Get members of Salesforce group with ID -> %s; calling -> %s",
            group_id,
            request_url,
        )

        return self.do_request(
            method="GET",
            url=request_url,
            headers=request_header,
            params=params,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get members of Salesforce group with ID -> {}".format(
                group_id
            ),
        )

    # end method definition

    def add_group_member(self, group_id: str, member_id: str) -> dict | None:
        """Add a user or group to a Salesforce group

        Args:
            group_id (str): ID of the Salesforce Group to add member to.
            member_id (str): ID of the user or group.

        Returns:
            dict | None: Dictionary with the Salesforce membership data or None if the request fails.

            Example response (id is the membership ID):
            {
                'id': '011Dn000000ELhwIAG',
                'success': True,
                'errors': []
            }
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_url = self.config()["groupMemberUrl"]

        request_header = self.request_header()

        payload = {"GroupId": group_id, "UserOrGroupId": member_id}

        logger.debug(
            "Add member with ID -> %s to Salesforce group with ID -> %s; calling -> %s",
            member_id,
            group_id,
            request_url,
        )

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            json_data=payload,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add member with ID -> {} to Salesforce group with ID -> {}".format(
                member_id, group_id
            ),
        )

    # end method definition

    def get_all_user_profiles(self) -> dict | None:
        """Get all user profiles

        Returns:
            dict | None: Dictionary with salesforce user profiles.

            Example response:
            {
                'totalSize': 15,
                'done': True,
                'records': [
                    {
                        ...
                        'attributes': {
                            'type': 'Profile',
                            'url': '/services/data/v52.0/sobjects/Profile/00eDn000001msL8IAI'},
                            'Id': '00eDn000001msL8IAI',
                            'Name': 'Standard User',
                            'CreatedById': '005Dn000001rRodIAE',
                            'CreatedDate': '2022-11-30T15:30:54.000+0000',
                            'Description': None,
                            'LastModifiedById': '005Dn000001rUacIAE',
                            'LastModifiedDate': '2024-02-08T17:46:17.000+0000',
                            'PermissionsCustomizeApplication': False,
                            'PermissionsEditTask': True,
                            'PermissionsImportLeads': False
                        }
                    }, ...
                ]
            }
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["queryUrl"]

        query = "SELECT Id, Name, CreatedById, CreatedDate, Description, LastModifiedById, LastModifiedDate, PermissionsCustomizeApplication, PermissionsEditTask, PermissionsImportLeads FROM Profile"

        return self.do_request(
            method="GET",
            url=request_url,
            headers=request_header,
            params={"q": query},
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Salesforce user profiles",
        )

    # end method definition

    def get_user_profile_id(self, profile_name: str) -> Optional[str]:
        """Get a user profile ID by profile name.

        Args:
            profile_name (str): Name of the User Profile.

        Returns:
            Optional[str]: Technical ID of the user profile.
        """

        return self.get_object_id_by_name(object_type="Profile", name=profile_name)

    # end method definition

    def get_user_id(self, username: str) -> Optional[str]:
        """Get a user ID by user name.

        Args:
            username (str): Name of the User.

        Returns:
            Optional[str]: Technical ID of the user
        """

        return self.get_object_id_by_name(
            object_type="User", name=username, name_field="Username"
        )

    # end method definition

    def get_user(self, user_id: str) -> dict | None:
        """Get a Salesforce user based on its ID.

        Args:
            user_id (str): ID of the Salesforce user

        Returns:
            dict | None: Dictionary with the Salesforce user data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["userUrl"] + user_id

        logger.debug(
            "Get Salesforce user with ID -> %s; calling -> %s", user_id, request_url
        )

        return self.do_request(
            method="GET",
            url=request_url,
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Salesforce user with ID -> {}".format(
                user_id
            ),
        )

    # end method definition

    def add_user(
        self,
        username: str,
        email: str,
        firstname: str,
        lastname: str,
        title: str | None = None,
        department: str | None = None,
        company_name: str = "Innovate",
        profile_name: Optional[str] = "Standard User",
        profile_id: Optional[str] = None,
        time_zone_key: Optional[str] = "America/Los_Angeles",
        email_encoding_key: Optional[str] = "ISO-8859-1",
        locale_key: Optional[str] = "en_US",
        alias: Optional[str] = None,
    ) -> dict | None:
        """Add a new Salesforce user. The password has to be set separately.

        Args:
            username (str): Login name of the new user
            email (str): Email of the new user
            firstname (str): First name of the new user.
            lastname (str): Last name of the new user.
            title (str): Title of the user.
            department (str): Department of the user.
            company_name (str): Name of the Company of the user.
            profile_name (str): Profile name like "Standard User"
            profile_id (str, optional): Profile ID of the new user. Defaults to None.
                                        Use method get_all_user_profiles() to determine
                                        the desired Profile for the user. Or pass the profile_name.
            time_zone_key (str, optional) in format country/city like "America/Los_Angeles",
            email_encoding_key (str, optional). Default is "ISO-8859-1".
            locale_key (str, optional). Default is "en_US".
            alias (str, optional): Alias of the new user. Defaults to None.

        Returns:
            dict | None: Dictionary with the Salesforce User data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["userUrl"]

        # if just a profile name is given then we determine the profile ID by the name:
        if profile_name and not profile_id:
            profile_id = self.get_user_profile_id(profile_name)

        payload = {
            "Username": username,
            "Email": email,
            "FirstName": firstname,
            "LastName": lastname,
            "ProfileId": profile_id,
            "Department": department,
            "CompanyName": company_name,
            "Title": title,
            "Alias": alias if alias else username,
            "TimeZoneSidKey": time_zone_key,  # Set default TimeZoneSidKey
            "LocaleSidKey": locale_key,  # Set default LocaleSidKey
            "EmailEncodingKey": email_encoding_key,  # Set default EmailEncodingKey
            "LanguageLocaleKey": locale_key,  # Set default LanguageLocaleKey
        }

        logger.debug(
            "Adding Salesforce user -> %s; calling -> %s", username, request_url
        )

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Salesforce user -> {}".format(username),
        )

    # end method definition

    def update_user(
        self,
        user_id: str,
        update_data: dict,
    ) -> dict:
        """Update a Salesforce user.

        Args:
            user_id (str): The Salesforce user ID.
            update_data (dict): Dictionary containing the fields to update.

        Returns:
            dict: Response from the Salesforce API.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()

        request_url = self.config()["userUrl"] + user_id

        logger.debug(
            "Update Salesforce user with ID -> %s; calling -> %s", user_id, request_url
        )

        return self.do_request(
            method="PATCH",
            url=request_url,
            headers=request_header,
            json_data=update_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update Salesforce user with ID -> {}".format(
                user_id
            ),
        )

    # end method definition

    def update_user_password(
        self,
        user_id: str,
        password: str,
    ) -> dict:
        """Update the password of a Salesforce user.

        Args:
            user_id (str): The Salesforce user ID.
            password (str): New user password.

        Returns:
            dict: Response from the Salesforce API.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()

        request_url = self.config()["userUrl"] + "{}/password".format(user_id)

        logger.debug(
            "Update password of Salesforce user with ID -> %s; calling -> %s",
            user_id,
            request_url,
        )

        update_data = {"NewPassword": password}

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            json_data=update_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update password of Salesforce user with ID -> {}".format(
                user_id
            ),
        )

    # end method definition

    def update_user_photo(
        self,
        user_id: str,
        photo_path: str,
    ) -> dict | None:
        """Update the Salesforce user photo.

        Args:
            user_id (str): Salesforce ID of the user
            photo_path (str): file system path with the location of the photo
        Returns:
            dict | None: Dictionary with the Salesforce User data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

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

        # Content Type = None is important as upload calls need
        # a multipart header that is automatically selected if None is used:
        request_header = self.request_header(content_type=None)

        data = {"json": json.dumps({"cropX": 0, "cropY": 0, "cropSize": 200})}
        request_url = self.config()["connectUrl"] + f"user-profiles/{user_id}/photo"
        files = {
            "fileUpload": (
                photo_path,
                photo_data,
                "application/octet-stream",
            )
        }

        logger.debug(
            "Update profile photo of Salesforce user with ID -> %s; calling -> %s",
            user_id,
            request_url,
        )

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            files=files,
            data=data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update profile photo of Salesforce user with ID -> {}".format(
                user_id
            ),
            verify=False,
        )

    # end method definition

    def add_account(
        self,
        account_name: str,
        account_number: str,
        account_type: str = "Customer",
        description: Optional[str] = None,
        industry: Optional[str] = None,
        website: Optional[str] = None,
        phone: Optional[str] = None,
        **kwargs: Any,
    ) -> dict | None:
        """Add a new Account object to Salesforce.

        Args:
            account_name (str): Name of the new Salesforce account.
            account_number (str): Number of the new Salesforce account (this is a logical number, not the technical ID)
            account_type (str): Type of the Salesforce account. Typical values are "Customer" or "Prospect".
            description(str, optional): Description of the new Salesforce account.
            industry (str, optional): Industry of the new Salesforce account. Defaults to None.
            website (str, optional): Website of the new Salesforce account. Defaults to None.
            phone (str, optional): Phone number of the new Salesforce account. Defaults to None.
            kwargs (Any): Additional values (e.g. custom fields)

        Returns:
            dict | None: Dictionary with the Salesforce Account data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["accountUrl"]

        payload = {
            "Name": account_name,
            "AccountNumber": account_number,
            "Type": account_type,
            "Industry": industry,
            "Description": description,
            "Website": website,
            "Phone": phone,
        }
        payload.update(kwargs)  # Add additional fields from kwargs

        logger.debug(
            "Adding Salesforce account -> '%s' (%s); calling -> %s",
            account_name,
            account_number,
            request_url,
        )

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Salesforce account -> '{}' ({})".format(
                account_name, account_number
            ),
        )

    # end method definition

    def add_product(
        self,
        product_name: str,
        product_code: str,
        description: str,
        price: float,
        **kwargs: Any,
    ) -> dict | None:
        """Add a new Product object to Salesforce.

        Args:
            product_name (str): Name of the Salesforce Product.
            product_code (str): Code of the Salesforce Product.
            description (str): Description of the Salesforce Product.
            price (float): Price of the Salesforce Product.

        Returns:
            dict | None: Dictionary with the Salesforce Product data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["productUrl"]

        payload = {
            "Name": product_name,
            "ProductCode": product_code,
            "Description": description,
            "Price__c": price,
        }
        payload.update(kwargs)  # Add additional fields from kwargs

        logger.debug(
            "Add Salesforce product -> '%s' (%s); calling -> %s",
            product_name,
            product_code,
            request_url,
        )

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Salesforce product -> '{}' ({})".format(
                product_name, product_code
            ),
        )

    # end method definition

    def add_opportunity(
        self,
        name: str,
        stage: str,
        close_date: str,
        amount: Union[int, float],
        account_id: str,
        description: str = None,
        **kwargs: Any,
    ) -> dict | None:
        """Add a new Opportunity object to Salesfoce.

        Args:
            name (str): Name of the Opportunity.
            stage (str): Stage of the Opportunity. Typical Value:
                         "Prospecting", "Qualification", "Value Proposition", "Negotiation/Review",
                         "Closed Won", "Closed Lost"
            close_date (str): Close date of the Opportunity. Should be in format YYYY-MM-DD.
            amount (Union[int, float]): Amount (expected revenue) of the opportunity.
                                        Can either be an integer or a float value.
            account_id (str): Technical ID of the related Salesforce Account.

        Returns:
            dict | None: Dictionary with the Salesforce Opportunity data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["opportunityUrl"]

        payload = {
            "Name": name,
            "StageName": stage,
            "CloseDate": close_date,
            "Amount": amount,
            "AccountId": account_id,
        }
        if description:
            payload["Description"] = description
        payload.update(kwargs)  # Add additional fields from kwargs

        logger.debug(
            "Add Salesforce opportunity -> '%s'; calling -> %s", name, request_url
        )

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Salesforce opportunity -> '{}'".format(name),
        )

    # end method definition

    def add_case(
        self,
        subject: str,
        description: str,
        status: str,
        priority: str,
        origin: str,
        account_id: str,
        owner_id: str,
        asset_id: Optional[str] = None,
        product_id: Optional[str] = None,
        **kwargs: Any,
    ) -> dict | None:
        """Add a new Case object to Salesforce. The case number is automatically created and can not be
           provided.

        Args:
            subject (str): Subject (title) of the case. It's like the name.
            description (str): Description of the case
            status (str): Status of the case. Typecal values: "New", "On Hold", "Escalated"
            priority (str): Priority of the case. Typical values: "High", "Medium", "Low".
            origin (str): origin (source) of the case. Typical values: "Email", "Phone", "Web"
            account_id (str): technical ID of the related Account
            owner_id (str): owner of the case
            asset_id (str): technical ID of the related Asset
            product_id (str): technical ID of the related Product
            kwargs (Any): additional values (e.g. custom fields)

        Returns:
            dict | None: Dictionary with the Salesforce Case data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["caseUrl"]

        payload = {
            "Subject": subject,
            "Description": description,
            "Status": status,
            "Priority": priority,
            "Origin": origin,
            "AccountId": account_id,
            "OwnerId": owner_id,
        }

        if asset_id:
            payload["AssetId"] = asset_id
        if product_id:
            payload["ProductId"] = product_id
        payload.update(kwargs)  # Add additional fields from kwargs

        logger.debug("Add Salesforce case -> '%s'; calling -> %s", subject, request_url)

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Salesforce case -> '{}'".format(subject),
        )

    # end method definition

    def add_asset(
        self,
        asset_name: str,
        product_id: str,
        serial_number: str,
        status: str,
        purchase_date: str,
        install_date: str,
        description: str | None = None,
        **kwargs: Any,
    ) -> dict | None:
        """Add a new Asset object to Salesforce.

        Args:
            asset_name (str): Name of the Asset.
            product_id (str): Related Product ID.
            serial_number (str): Serial Number of the Asset.
            status (str): Status of the Asset. Typical values are "Purchased", "Shipped", "Installed", "Registered", "Obsolete"
            purchase_date (str): Purchase date of the Asset.
            install_date (str): Install date of the Asset.
            description (str): Description of the Asset.
            kwargs (Any): Additional values (e.g. custom fields)

        Returns:
            dict | None: Dictionary with the Salesforce Asset data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["assetUrl"]

        payload = {
            "Name": asset_name,
            "ProductId": product_id,
            "SerialNumber": serial_number,
            "Status": status,
            "PurchaseDate": purchase_date,
            "InstallDate": install_date,
        }
        if description:
            payload["Description"] = description
        payload.update(kwargs)  # Add additional fields from kwargs

        logger.debug(
            "Add Salesforce asset -> '%s'; calling -> %s", asset_name, request_url
        )

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Salesforce asset -> '{}'".format(asset_name),
        )

    # end method definition

    def add_contract(
        self,
        account_id: str,
        start_date: str,
        contract_term: int,
        status: str = "Draft",
        description: Optional[str] = None,
        contract_type: Optional[str] = None,
        **kwargs: Any,
    ) -> dict | None:
        """Add a new Contract object to Salesforce.

        Args:
            account_id (str): Technical ID of the related Salesforce Account object.
            start_date (str): Start date of the Contract. Use YYYY-MM-DD notation.
            contract_term (int): Term of the Contract in number of months, e.g. 48 for 4 years term.
                                 The end date of the contract will be calculated from start date + term.
            contract_type (str): Type of the Contract. Typical values are "Subscription",
                                 "Maintenance", "Support", "Lease", or "Service".
            status (str): Status of the Contract. Typical values are "Draft", "Activated", or "In Approval Process"

        Returns:
            dict | None: Dictionary with the Salesforce user data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            self.authenticate()

        request_header = self.request_header()
        request_url = self.config()["contractUrl"]

        payload = {
            "AccountId": account_id,
            "StartDate": start_date,
            "ContractTerm": contract_term,
            "Status": status,
        }
        if description:
            payload["Description"] = description
        if contract_type:
            payload["ContractType"] = contract_type
        payload.update(kwargs)  # Add additional fields from kwargs

        logger.debug(
            "Adding Salesforce contract for account with ID -> %s; calling -> %s",
            account_id,
            request_url,
        )

        return self.do_request(
            method="POST",
            url=request_url,
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Salesforce contract for account with ID -> {}".format(
                account_id
            ),
        )

    # end method definition

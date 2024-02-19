"""
Salesforce Module to interact with the Salesforce API

Class: Salesforce
Methods:

__init__ : class initializer
config : Returns config data set
credentials: Returns the token data
request_header: Returns the request header for Salesforce API calls
parse_request_response: Parse the REST API responses and convert
                        them to Python dict in a safe way
exist_result_item: Check if an dict item is in the response
                   of the Salesforce API call
get_result_value: Check if a defined value (based on a key) is in the Salesforce API response

authenticate : Authenticates at Salesforce API

get_user: Get a Salesforce user based on its ID.
add_user: Add a new Salesforce user.

get_object: Get a Salesforce object based on a defined
            field value and return selected result fields.
add_object: Add object to Salesforce. This is a generic wrapper method
            for the actual add methods.
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

import json
import logging

from typing import Optional, Union, Any
import requests

logger = logging.getLogger("pyxecm.customizer.salesforce")

request_login_headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
}

REQUEST_TIMEOUT = 60

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

        salesforce_config = {}

        # Set the authentication endpoints and credentials
        salesforce_config["baseUrl"] = base_url
        salesforce_config["clientId"] = client_id
        salesforce_config["clientSecret"] = client_secret
        salesforce_config["username"] = username
        salesforce_config["password"] = password
        salesforce_config["securityToken"] = security_token
        if authorization_url:
            salesforce_config["authenticationUrl"] = authorization_url
        else:
            salesforce_config["authenticationUrl"] = (
                salesforce_config["baseUrl"] + "/services/oauth2/token"
            )

        # Set the data for the token request
        salesforce_config["authenticationData"] = {
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "username": username,
            "password": password,
        }

        self._config = salesforce_config

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
            logger.info(
                "Session still valid - return existing access token -> %s",
                str(self._access_token),
            )
            return self._access_token

        request_url = self.config()["authenticationUrl"]
        request_header = request_login_headers

        logger.info("Requesting Salesforce Access Token from -> %s", request_url)

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
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/query/"

        query = f"SELECT Id FROM {object_type} WHERE {name_field} = '{name}'"

        retries = 0
        while True:
            response = requests.get(
                request_url,
                headers=request_header,
                params={"q": query},
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                response = self.parse_request_response(response)
                object_id = self.get_result_value(response, "Id")
                return object_id
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to get Salesforce object ID for object type -> %s and object name -> %s; status -> %s; error -> %s",
                    object_type,
                    name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_profile_id(self, profile_name: str) -> Optional[str]:
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
        """

        if not self._access_token or not self._instance_url:
            logger.error("Authentication required.")
            return None
        if search_field and not search_value:
            logger.error(
                "No search value has been provided for search field -> %s!",
                search_field,
            )
            return None
        if not result_fields:
            logger.info(
                "No result fields defined. Using 'FIELDS(STANDARD)' to deliver all standard fields of the object."
            )
            result_fields = ["FIELDS(STANDARD)"]

        query = "SELECT {} FROM {}".format(", ".join(result_fields), object_type)
        if search_field and search_value:
            query += " WHERE {}='{}'".format(search_field, search_value)
        query += " LIMIT {}".format(str(limit))

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/query/?q={query}"

        logger.info(
            "Sending query -> %s to Salesforce; calling -> %s", query, request_url
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=30)
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to retrieve Salesforce object -> %s with %s = %s; status -> %s; error -> %s",
                    object_type,
                    search_field,
                    search_value,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def add_object(self, object_type: str, **kwargs: Any) -> dict | None:
        """Add object to Salesforce. This is a generic wrapper method
           for the actual add methods.

        Args:
            object_type (str): Type of the Salesforce business object, like "Account" or "Case".

        Returns:
            dict | None: Dictionary with the Salesforce Case data or None if the request fails.
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

    def get_user(self, user_id: str) -> dict | None:
        """Get a Salesforce user based on its ID.

        Args:
            user_id (str): ID of the Salesforce user

        Returns:
            dict | None: Dictionary with the Salesforce user data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = (
            f"{self._instance_url}/services/data/v52.0/sobjects/User/{user_id}"
        )

        logger.info(
            "Get Salesforce user with ID -> %s; calling -> %s", user_id, request_url
        )

        retries = 0
        while True:
            response = requests.get(
                request_url, headers=request_header, timeout=REQUEST_TIMEOUT
            )
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to get Salesforce user -> %s; status -> %s; error -> %s",
                    user_id,
                    response.status_code,
                    response.text,
                )
                return None

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
                            'CreatedById':
                            '005Dn000001rRodIAE',
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
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/query/"

        query = "SELECT Id, Name, CreatedById, CreatedDate, Description, LastModifiedById, LastModifiedDate, PermissionsCustomizeApplication, PermissionsEditTask, PermissionsImportLeads FROM Profile"

        retries = 0
        while True:
            response = requests.get(
                request_url,
                headers=request_header,
                params={"q": query},
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to get Salesforce user profiles; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def add_user(
        self,
        username: str,
        email: str,
        password: str,
        firstname: str,
        lastname: str,
        profile_id: Optional[str] = None,
        alias: Optional[str] = None,
    ) -> dict | None:
        """Add a new Salesforce user.

        Args:
            username (str): Login name of the new user
            email (str): Email of the new user
            password (str): Password of the new user
            firstname (str): First name of the new user.
            lastname (str): Last name of the new user.
            profile_id (str, optional): Profile ID of the new user. Defaults to None.
                                        Use method get_all_user_profiles() to determine
                                        the desired Profile for the user.
            alias (str, optional): Alias of the new user. Defaults to None.

        Returns:
            dict | None: Dictionary with the Salesforce User data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/sobjects/User/"

        payload = {
            "Username": username,
            "Email": email,
            "Password": password,
            "FirstName": firstname,
            "LastName": lastname,
            "ProfileId": profile_id,
            "Alias": alias,
        }

        logger.info(
            "Adding Salesforce user -> %s; calling -> %s", username, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to add Salesforce user -> %s; status -> %s; error -> %s",
                    username,
                    response.status_code,
                    response.text,
                )
                return None

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
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/sobjects/Account/"

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

        logger.info(
            "Adding Salesforce account -> %s; calling -> %s", account_name, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to add Salesforce account -> %s; status -> %s; error -> %s",
                    account_name,
                    response.status_code,
                    response.text,
                )
                return None

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
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/sobjects/Product2/"

        payload = {
            "Name": product_name,
            "ProductCode": product_code,
            "Description": description,
            "Price__c": price,
        }
        payload.update(kwargs)  # Add additional fields from kwargs

        logger.info(
            "Add Salesforce product -> %s; calling -> %s", product_name, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to add Salesforce product -> %s; status -> %s; error -> %s",
                    product_name,
                    response.status_code,
                    response.text,
                )
                return None

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
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/sobjects/Opportunity/"

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

        logger.info(
            "Add Salesforce opportunity -> %s; calling -> %s", name, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to add Salesforce opportunity -> %s; status -> %s; error -> %s",
                    name,
                    response.status_code,
                    response.text,
                )
                return None

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
            asset_id (str): technical ID of the related Asset
            product_id (str): technical ID of the related Product
            kwargs (Any): additional values (e.g. custom fields)

        Returns:
            dict | None: Dictionary with the Salesforce Case data or None if the request fails.
        """

        if not self._access_token or not self._instance_url:
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/sobjects/Case/"

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

        logger.info("Add Salesforce case -> %s; calling -> %s", subject, request_url)

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to add Salesforce case -> %s; status -> %s; error -> %s",
                    subject,
                    response.status_code,
                    response.text,
                )
                return None

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
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/sobjects/Asset/"

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

        logger.info(
            "Add Salesforce asset -> %s; calling -> %s", asset_name, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to add Salesforce user -> %s; status -> %s; error -> %s",
                    asset_name,
                    response.status_code,
                    response.text,
                )
                return None

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
            logger.error("Authentication required.")
            return None

        request_header = self.request_header()
        request_url = f"{self._instance_url}/services/data/v52.0/sobjects/Contract/"

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

        logger.info(
            "Adding Salesforce contract for account ID -> %s; calling -> %s",
            account_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                return self.parse_request_response(response)
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                request_header = self.request_header()
                retries += 1
            else:
                logger.error(
                    "Failed to add Salesforce contract for account ID -> %s; status -> %s; error -> %s",
                    account_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

"""
PHT is an OpenText internal application aiming at creating a common naming reference for Engineering Products and
track all product-related data. It also provides an approved reporting hierarchy.
See: https://pht.opentext.com

Class: PHT
Methods:

__init__ : class initializer
config : Returns config data set
get_data: Get the Data object that holds all processed PHT products
request_header: Returns the request header for ServiceNow API calls
parse_request_response: Parse the REST API responses and convert
                        them to Python dict in a safe way

authenticate : Authenticates at ServiceNow API

get_attributes: Get a list of all product attributes (schema) of PHT
get_business_units: Get the list of PHT Business Units
get_product_families: Get the list of PHT product families
get_products: Get the list of PHT products
get_master_products: Get the list of PHT master products
filter_products: Get a list of filtered PHT products
load_products: Load products into a data frame.

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging

import requests
from requests.auth import HTTPBasicAuth
from pyxecm.helper.data import Data

logger = logging.getLogger("pyxecm.customizer.pht")

REQUEST_HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

REQUEST_TIMEOUT = 60


class PHT(object):
    """Used to retrieve data from OpenText PHT."""

    _config: dict
    _session = None

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
    ):
        """Initialize the PHT object

        Args:
            base_url (str): base URL of the ServiceNow tenant
            username (str): user name in Saleforce
            password (str): password of the user
        """

        pht_config = {}

        # Store the credentials and parameters in a config dictionary:
        pht_config["baseUrl"] = base_url
        pht_config["username"] = username
        pht_config["password"] = password

        pht_config["restUrl"] = pht_config["baseUrl"] + "/api"
        pht_config["attributeUrl"] = pht_config["restUrl"] + "/attribute"
        pht_config["businessUnitUrl"] = pht_config["restUrl"] + "/business-unit"
        pht_config["productFamilyUrl"] = pht_config["restUrl"] + "/product-family"
        pht_config["productUrl"] = pht_config["restUrl"] + "/product"
        pht_config["searchUrl"] = pht_config["productUrl"] + "/product/search"
        pht_config["teamUrl"] = pht_config["restUrl"] + "/team"
        pht_config["componentUrl"] = pht_config["restUrl"] + "/component"
        pht_config["masterProductUrl"] = pht_config["restUrl"] + "/master-product"

        self._config = pht_config

        self._session = requests.Session()

        self._data = Data()

    # end method definition

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    # end method definition

    def get_data(self) -> Data:
        """Get the Data object that holds all processed PHT products

        Returns:
            Data: Datastructure with all processed PHT product data.
        """

        return self._data

    # end method definition

    def request_header(self, content_type: str = "") -> dict:
        """Returns the request header used for Application calls.
           Consists of Bearer access token and Content Type

        Args:
            content_type (str, optional): custom content type for the request
        Return:
            dict: request header values
        """

        request_header = {}

        request_header = REQUEST_HEADERS

        if content_type:
            request_header["Content-Type"] = content_type

        return request_header

    # end method definition

    def parse_request_response(
        self,
        response_object: requests.Response,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> list | None:
        """Converts the request response (JSon) to a Python list in a safe way
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
            list: response information or None in case of an error
        """

        if not response_object:
            return None

        try:
            if response_object.text:
                list_object = json.loads(response_object.text)
            else:
                list_object = vars(response_object)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSON. {}; error -> {}".format(
                    additional_error_message, exception
                )
            else:
                message = "Cannot decode response as JSON; error -> {}".format(
                    exception
                )
            if show_error:
                logger.error(message)
            else:
                logger.warning(message)
            return None
        else:
            return list_object

    # end method definition

    def authenticate(self) -> str | None:
        """Authenticate at PHT with basic authentication."""

        self._session.headers.update(self.request_header())

        username = self.config()["username"]
        password = self.config()["password"]
        if not self._session:
            self._session = requests.Session()
        self._session.auth = HTTPBasicAuth(username, password)

        return self._session.auth

    # end method definition

    def get_attributes(self) -> list | None:
        """Get a list of all product attributes (schema) of PHT

        Returns:
            list | None: list of product attributes

            Example:
            [
                {
                    'id': 28,
                    'uuid': '43ba5852-eb83-11ed-a752-00505682262c',
                    'name': 'UBM SCM Migration JIRA/ValueEdge',
                    'description': 'Identifies the Issue to track work for the SCM migration for this project.\nIts a free text field and no validation with JIRA/ValueEdge will take place',
                    'type': 'TEXT',
                    'attributeCategory': {
                        'id': 2,
                        'name': 'Auxiliary assignment'
                    },
                    'showDefault': False,
                    'restricted': True,
                    'allowScopeChain': True,
                    'visibleToAll': False,
                    'deleted': False,
                    'attributeOptions': [],
                    'attributeScopes': [],
                    'allowedTeams': []
                }
            ]
        """

        request_header = self.request_header()
        request_url = self.config()["attributeUrl"]

        retries = 0

        while True:
            response = self._session.get(url=request_url, headers=request_header)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate()
                retries += 1
            else:
                logger.error(
                    "Failed to get PHT attributes; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_business_units(self) -> list | None:
        """Get the list of PHT Business Units

        Returns:
            list | None: list of the known business units.

            Example:
            [
                {
                    'id': 1,
                    'name': 'Content Services',
                    'leaderModel': {
                        'id': 219,
                        'domain': 'mcybala',
                        'email': 'mcybala@opentext.com',
                        'name': 'Michael Cybala',
                        'role': None,
                        'status': 'ACTIVE',
                        'location': 'Kempten, DEU',
                        'title': 'VP, Software Engineering',
                        'type': 'OTHERS'
                    },
                    'pmLeaderModel': {
                        'id': 350,
                        'domain': 'mdiefenb',
                        'email': 'mdiefenb@opentext.com',
                        'name': 'Marc Diefenbruch',
                        'role': None,
                        'status': 'ACTIVE',
                        'location': 'Virtual, DEU',
                        'title': 'VP, Product Management',
                        'type': 'OTHERS'
                    },
                    'sltOwnerModel': {
                        'id': 450,
                        'domain': 'jradko',
                        'email': 'jradko@opentext.com',
                        'name': 'John Radko',
                        'role': None,
                        'status': 'ACTIVE',
                        'location': 'Gaithersburg, MD, USA',
                        'title': 'SVP, Software Engineering',
                        'type': 'OTHERS'
                    },
                    'status': 'ACTIVE',
                    'engineering': True,
                    'attributes': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}],
                    'leader': 'Michael Cybala',
                    'leaderDomain': 'mcybala',
                    'pmLeader': 'Marc Diefenbruch',
                    'pmLeaderDomain': 'mdiefenb',
                    'sltOwner': 'John Radko',
                    'sltOwnerDomain': 'jradko'
                }
            ]
        """

        request_header = self.request_header()
        request_url = self.config()["businessUnitUrl"]

        retries = 0

        while True:
            response = self._session.get(url=request_url, headers=request_header)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate()
                retries += 1
            else:
                logger.error(
                    "Failed to get PHT business units; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_product_families(self) -> list | None:
        """Get the list of PHT product families

        Returns:
            list | None: list of the known product families.
        """

        request_header = self.request_header()
        request_url = self.config()["productFamilyUrl"]

        retries = 0

        while True:
            response = self._session.get(url=request_url, headers=request_header)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate()
                retries += 1
            else:
                logger.error(
                    "Failed to get PHT product families; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_products(self) -> list | None:
        """Get the list of PHT products

        Returns:
            list | None: list of the known products.
        """

        request_header = self.request_header()
        request_url = self.config()["productUrl"]

        retries = 0

        while True:
            response = self._session.get(url=request_url, headers=request_header)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate()
                retries += 1
            else:
                logger.error(
                    "Failed to get PHT products; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_master_products(self) -> list | None:
        """Get the list of PHT master products

        Returns:
            list | None: list of the known master products.
        """

        request_header = self.request_header()
        request_url = self.config()["masterProductUrl"]

        retries = 0

        while True:
            response = self._session.get(url=request_url, headers=request_header)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate()
                retries += 1
            else:
                logger.error(
                    "Failed to get PHT master products; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def filter_products(self, filter_definition: dict | None = None) -> list | None:
        """Get a list of filtered PHT products

        Args:
            filter_definition (dict): a dictionary of filter conditions.
            Example filters:
                businessUnitName: <String>
                productFamilyName: <String>
                productName: <String>
                productSyncId: <String>
                productStatus: ACTIVE | INACTIVE | MAINTENANCE
                productManager: <String>
                developmentManager: <String>
                attributeOperator: AND | OR
                attributes: {
                    "<AttributeName>": {
                        "compare": CONTAINS | EXISTS | DOES_NOT_EXISTS,
                        "values": List<String>
                    },
                    ...
                },
                includeAttributes: true | false
        Returns:
            list | None: list of matching products.
        """

        if not filter_definition:
            return self.get_products()

        request_header = self.request_header()
        request_url = self.config()["productUrl"] + "/filtered"
        request_data = filter_definition

        retries = 0

        while True:
            response = self._session.post(
                url=request_url, headers=request_header, json=request_data
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate()
                retries += 1
            else:
                logger.error(
                    "Failed to get PHT master products; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def load_products(self, product_list: list = None) -> bool:
        """Load products into a data frame in the self._data object

        Args:
            product_list (list, optional): listn of products - if already avaiable. Defaults to None.

        Returns:
            bool: True if successful, False otherwise.
        """

        if not product_list:
            product_list = self.get_products()

        self._data = Data(product_list)

        if self._data:
            return True

        return False

    # end method definition

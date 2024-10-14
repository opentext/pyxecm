"""
PHT stands for Product Hierarchy Tracker and is an OpenText internal application aiming at creating a common naming reference for Engineering Products and
track all product-related data. It also provides an approved reporting hierarchy.
See: https://pht.opentext.com

Class: PHT
Methods:

__init__ : class initializer
config : Returns config data set
get_data: Get the Data object that holds all processed PHT products
request_header: Returns the request header for ServiceNow API calls
do_request: Call an PHT REST API in a safe way
parse_request_response: Parse the REST API responses and convert
                        them to Python dict in a safe way

authenticate : Authenticates at ServiceNow API

get_attributes: Get a list of all product attributes (schema) of PHT
get_business_units: Get the list of PHT Business Units
get_product_families: Get the list of PHT product families

get_products: Get the list of PHT products
get_products_filtered: Get a list of filtered PHT products
get_product: Get a specific product in PHT
search_products: Search products in PHT

get_master_products: Get the list of PHT master products
get_master_products_filtered: Get a list of filtered PHT master products
get_master_product: Get a specific product in PHT

get_teams: Get a list of all teams in PHT.
get_team: Get a specific team in PHT.

get_componets: Get a list of all components in PHT.
get_components_filtered: Get a list of filtered PHT components.
get_component: Get a specific component in PHT.
search_components: Search components in PHT

load_products: Load products into a data frame.

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import time

import requests
from requests.auth import HTTPBasicAuth
from pyxecm.helper.data import Data

logger = logging.getLogger("pyxecm.customizer.pht")

REQUEST_HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

REQUEST_TIMEOUT = 60
REQUEST_RETRY_DELAY = 20
REQUEST_MAX_RETRIES = 2

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
        pht_config["productFilteredUrl"] = pht_config["productUrl"] + "/filtered"
        pht_config["productSearchUrl"] = pht_config["productUrl"] + "/search"
        pht_config["productUsersUrl"] = pht_config["productUrl"] + "/users"
        pht_config["teamUrl"] = pht_config["restUrl"] + "/team"
        pht_config["masterProductUrl"] = pht_config["restUrl"] + "/master-product"
        pht_config["masterProductFilteredUrl"] = (
            pht_config["masterProductUrl"] + "/filtered"
        )
        pht_config["componentUrl"] = pht_config["restUrl"] + "/component"
        pht_config["componentFilteredUrl"] = pht_config["componentUrl"] + "/filtered"
        pht_config["componentSearchUrl"] = pht_config["componentUrl"] + "/search"
        pht_config["componentUsersUrl"] = pht_config["componentUrl"] + "/users"

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

    def do_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        data: dict | None = None,
        files: dict | None = None,
        timeout: int | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        retry_forever: bool = False,
    ) -> dict | None:
        """Call an PHT REST API in a safe way

        Args:
            url (str): URL to send the request to.
            method (str, optional): HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional): Request Headers. Defaults to None.
            json (dict | None, optional): Request payload. Defaults to None.
            files (dict | None, optional): Dictionary of {"name": file-tuple} for multipart encoding upload.
                                           file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            timeout (int | None, optional): Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional): Whether or not an error should be logged in case of a failed REST call.
                                         If False, then only a warning is logged. Defaults to True.
            failure_message (str, optional): Specific error message. Defaults to "".
            max_retries (int, optional): How many retries on Connection errors? Default is REQUEST_MAX_RETRIES.
            retry_forever (bool, optional): Eventually wait forever - without timeout. Defaults to False.

        Returns:
            dict | None: Response of PHT REST API or None in case of an error.
        """

        retries = 0
        while True:
            try:
                response = self._session.request(
                    method=method,
                    url=url,
                    json=data,
                    files=files,
                    headers=headers,
                    timeout=timeout,
                )

                if response.ok:
                    if success_message:
                        logger.debug(success_message)
                    return self.parse_request_response(response)
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    logger.debug("Session has expired - try to re-authenticate...")
                    self.authenticate()
                    retries += 1
                else:
                    # Handle plain HTML responses to not pollute the logs
                    content_type = response.headers.get("content-type", None)
                    if content_type == "text/html":
                        response_text = "HTML content (see debug log)"
                    else:
                        response_text = response.text

                    if show_error:
                        logger.error(
                            "%s; status -> %s; error -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )
                    else:
                        logger.warning(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )

                    if content_type == "text/html":
                        logger.debug(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
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

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get PHT attributes!",
        )

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

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get PHT business units!",
        )

    # end method definition

    def get_product_families(self) -> list | None:
        """Get the list of PHT product families

        Returns:
            list | None: list of the known product families.
        """

        request_header = self.request_header()
        request_url = self.config()["productFamilyUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get PHT product families!",
        )

    # end method definition

    def get_products(self) -> list | None:
        """Get the list of PHT products

        Returns:
            list | None: list of the known products.
        """

        request_header = self.request_header()
        request_url = self.config()["productUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get PHT products!",
        )

    # end method definition

    def get_products_filtered(
        self, filter_definition: dict | None = None
    ) -> list | None:
        """Get a list of filtered PHT products

        Args:
            filter_definition (dict): a dictionary of filter conditions.
            Example filters:
            {
                businessUnitName: <String>,
                productFamilyName: <String>,
                productName: <String>,
                productSyncId: <String>,
                productStatus: ACTIVE | INACTIVE | MAINTENANCE,
                productManager: <String>,
                developmentManager: <String>,
                attributeOperator: AND | OR,
                attributes: {
                    "<AttributeName>": {
                        "compare": CONTAINS | EXISTS | DOES_NOT_EXISTS,
                        "values": List<String>
                    },
                    ...
                },
                includeAttributes: true | false
            }
        Returns:
            list | None: list of matching products.
        """

        if not filter_definition:
            return self.get_products()

        request_header = self.request_header()
        request_url = self.config()["productFilteredUrl"]
        request_data = filter_definition

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=request_data,
            timeout=None,
            failure_message="Failed to get filtered PHT products!",
        )

    # end method definition

    def get_product(self, sync_id: int) -> dict | None:
        """Get a specific product in PHT.

        Returns:
            dict | None: product data matching the sync ID
        """

        request_header = self.request_header()
        request_url = self.config()["productUrl"] + "/" + str(sync_id)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT product with sync ID -> {}!".format(
                sync_id
            ),
        )

    # end method definition

    def search_products(
        self, query: str, business_unit: str | None = None, family: str | None = None
    ) -> list | None:
        """Search for specific product in PHT by the product name.

        Returns:
            str: search term matches any part of the component name
        """

        request_header = self.request_header()
        request_url = self.config()["componentSearchUrl"] + "?q=" + query
        if business_unit:
            request_url += "&businessUnit=" + business_unit
        if family:
            request_url += "&family=" + family

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT components matching -> {}!".format(
                query
            ),
        )

    # end method definition

    def get_master_products(self) -> list | None:
        """Get the list of PHT master products

        Returns:
            list | None: list of the known master products.
        """

        request_header = self.request_header()
        request_url = self.config()["masterProductUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get PHT master products!",
        )

    # end method definition

    def get_master_products_filtered(
        self, filter_definition: dict | None = None
    ) -> list | None:
        """Get a list of filtered PHT master products

        Args:
            filter_definition (dict): a dictionary of filter conditions.
            Example filters:
            {
                businessUnitName: <String>,
                productFamilyName: <String>,
                masterproductName: <String>,
                masterproductSyncId: <String>,
                masterproductStatus: ACTIVE | INACTIVE | MAINTENANCE,
                productManagerDomain: <String>,
                attributeOperator: AND | OR,
                attributes: {
                    "<AttributeName>": {
                        "compare": CONTAINS | EXISTS | DOES_NOT_EXISTS,
                        "values": List<String>
                    },
                    ...
                },
                includeAttributes: true | false
                includeLinkedProducts: true | false
            }
        Returns:
            list | None: list of matching products.
        """

        if not filter_definition:
            return self.get_products()

        request_header = self.request_header()
        request_url = self.config()["masterProductFilteredUrl"]
        request_data = filter_definition

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=request_data,
            timeout=None,
            failure_message="Failed to get filtered PHT master products!",
        )

    # end method definition

    def get_master_product(self, sync_id: int) -> dict | None:
        """Get a specific product in PHT.

        Returns:
            dict | None: product data matching the sync ID
        """

        request_header = self.request_header()
        request_url = self.config()["productUrl"] + "/" + str(sync_id)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT product with sync ID -> {}!".format(
                sync_id
            ),
        )

    # end method definition

    def get_teams(self) -> list:
        """Get a list of all teams in PHT.

        Returns:
            list: list of PHT teams
        """

        request_header = self.request_header()
        request_url = self.config()["teamUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT teams!",
        )

    # end method definition

    def get_team(self, team_id: int) -> dict | None:
        """Get a specific team in PHT.

        Returns:
            dict | None: dict of the PHT team
        """

        request_header = self.request_header()
        request_url = self.config()["teamUrl"] + "/" + str(team_id)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT teams!",
        )

    # end method definition

    def get_components(self) -> list:
        """Get a list of all components in PHT.

        Returns:
            list: list of PHT components

        Example result:
        [
            {
                'id': 468,
                'syncId': '6380c3da-8ded-40cd-8071-61f6721956f5',
                'name': 'XOTE',
                'developmentManager': {
                    'id': 237,
                    'domain': 'kurt',
                    'email': 'kurt.junker@opentext.com',
                    'name': 'Kurt Junker',
                    'role': None,
                    'status': 'ACTIVE',
                    'location': 'Grasbrunn, DEU',
                    'title': 'Sr. Manager, Software Engineering',
                    'type': 'OTHERS'
                },
                'componentCategory': {
                    'id': 2,
                    'name': 'Testing scripts',
                    'shortName': 'Testing scripts'
                },
                'comment': 'Test Framework maintained and used by Core Archive Team',
                'status': 'MAINTENANCE',
                'attributes': [
                    {
                        'id': 409,
                        'attribute': {
                            'id': 4,
                            'uuid': '03e228b5-9eae-11ea-96ab-00505682bce9',
                            'name': 'Build Advocate',
                            'description': 'Primary contact for build items.',
                            'type': 'USER'
                        },
                        'value': 'burkhard',
                        'textAttributeValue': None,
                        'userAttributeValue': {
                            'id': 414,
                            'domain': 'burkhard',
                            'email': 'burkhard.meier@opentext.com',
                            'name': 'Burkhard Meier',
                            'role': None,
                            'status': 'ACTIVE',
                            'location': 'Virtual, DEU',
                            'title': 'Principal Software Engineer',
                            'type': 'DEV'
                        },
                        'listAttributeValue': None
                    },
                    ...
                ],
                'sourceRepos': [],
                'artifacts': [],
                'products': [],
                'teams': [],
                'users': [],
                'guestTeams': [],
                'guestUsers': [],
                'relatedLOBS': []
            }
        ]
        """

        request_header = self.request_header()
        request_url = self.config()["componentUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT components!",
        )

    # end method definition

    def get_components_filtered(
        self, filter_definition: dict | None = None
    ) -> list | None:
        """Get a list of filtered PHT components

        Args:
            filter_definition (dict): a dictionary of filter conditions.
            Example filters:
            {
                componentName: <String>,
                componentSyncId: <String>,
                componentStatus: ACTIVE | INACTIVE | MAINTENANCE,
                developmentManager: <String>,
                attributeOperator: AND | OR,
                attributes: {
                    "<AttributeName>": {
                        "compare": CONTAINS | EXISTS | DOES_NOT_EXISTS,
                        "values": List<String>
                    },
                    ...
                },
                includeAttributes: true | false
            }
        Returns:
            list | None: list of matching components.
        """

        if not filter_definition:
            return self.get_products()

        request_header = self.request_header()
        request_url = self.config()["masterProductFilteredUrl"]
        request_data = filter_definition

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=request_data,
            timeout=None,
            failure_message="Failed to get filtered PHT master products!",
        )

    # end method definition

    def get_component(self, sync_id: int) -> dict | None:
        """Get a specific component in PHT.

        Returns:
            dict | None: PHT component
        """

        request_header = self.request_header()
        request_url = self.config()["componentUrl"] + "/" + str(sync_id)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT component with sync ID -> {}!".format(
                sync_id
            ),
        )

    # end method definition

    def search_components(self, query: str) -> list | None:
        """Search for specific components in PHT by the component name.

        Returns:
            str: search term matches any part of the component name
        """

        request_header = self.request_header()
        request_url = self.config()["componentSearchUrl"] + "?q=" + query

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT components matching -> {}!".format(
                query
            ),
        )

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

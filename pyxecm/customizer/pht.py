"""PHT stands for Product Hierarchy Tracker.

It is an OpenText internal application aiming at creating a common naming reference for Engineering Products and
track all product-related data. It also provides an approved reporting hierarchy.

See: https://pht.opentext.com

Request for User Access Token: https://confluence.opentext.com/display/RDOT/Request+a+User+Access+Token
PHT API Documentation: https://confluence.opentext.com/display/RDOT/PHT+API+Documentation
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import time

import requests
from requests.auth import HTTPBasicAuth

from pyxecm.helper import Data

default_logger = logging.getLogger("pyxecm.customizer.pht")

REQUEST_HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

REQUEST_TIMEOUT = 60
REQUEST_RETRY_DELAY = 20
REQUEST_MAX_RETRIES = 2


class PHT:
    """Class PHT is used to retrieve data from OpenText PHT. It is a pure read-only access."""

    logger: logging.Logger = (default_logger,)

    _config: dict
    _session = None
    _business_unit_exclusions = None
    _business_unit_inclusions = None
    _product_exclusions = None
    _product_inclusions = None
    _product_category_exclusions = None
    _product_category_inclusions = None
    _product_status_exclusions = None
    _product_status_inclusions = None

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        business_unit_exclusions: list | None = None,
        business_unit_inclusions: list | None = None,
        product_exclusions: list | None = None,
        product_inclusions: list | None = None,
        product_category_exclusions: list | None = None,
        product_category_inclusions: list | None = None,
        product_status_exclusions: list | None = None,
        product_status_inclusions: list | None = None,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the PHT object.

        Args:
            base_url (str):
                The base URL of PHT.
            username (str):
                The user name to access PHT.
            password (str):
                The password of the user.
            business_unit_exclusions (list | None, optional):
                A black list for business units to exclude. Default = None.
            business_unit_inclusions (list | None, optional):
                A white list for business units to include. Default = None.
            product_exclusions (list | None, optional):
                A black list for products to exclude. Default = None.
            product_inclusions (list | None, optional):
                A white list for products to include. Default = None.
            product_category_exclusions (list | None, optional):
                A black list for product categories to exclude. Default = None.
            product_category_inclusions (list | None, optional):
                A white list for product categories to include. Default = None.
            product_status_exclusions (list | None, optional):
                A back list of product status to exclude. Only products with status NOT on
                this list will be included. Default = None.
            product_status_inclusions (list | None, optional):
                A white list of product status to exclude. Only products with status on
                this list will be included. Default = None.
            logger (logging.Logger):
                The logging object used for all log messages. Default = default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("pht")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

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
        pht_config["masterProductFilteredUrl"] = pht_config["masterProductUrl"] + "/filtered"
        pht_config["componentUrl"] = pht_config["restUrl"] + "/component"
        pht_config["componentFilteredUrl"] = pht_config["componentUrl"] + "/filtered"
        pht_config["componentSearchUrl"] = pht_config["componentUrl"] + "/search"
        pht_config["componentUsersUrl"] = pht_config["componentUrl"] + "/users"

        self._config = pht_config

        self._session = requests.Session()

        self._data = Data(logger=self.logger)

        self._business_unit_exclusions = business_unit_exclusions
        self._business_unit_inclusions = business_unit_inclusions
        self._product_exclusions = product_exclusions
        self._product_inclusions = product_inclusions
        self._product_category_exclusions = product_category_exclusions
        self._product_category_inclusions = product_category_inclusions
        self._product_status_exclusions = product_status_exclusions
        self._product_status_inclusions = product_status_inclusions

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict:
                The configuration dictionary.

        """
        return self._config

    # end method definition

    def get_data(self) -> Data:
        """Get the Data object that holds all processed PHT products.

        Returns:
            Data:
                Datastructure with all processed PHT product data.

        """

        return self._data

    # end method definition

    def request_header(self, content_type: str = "") -> dict:
        """Return the request header used for Application calls.

        Consists of Bearer access token and Content Type

        Args:
            content_type (str, optional):
                Custom content type for the request.
                Typical values:
                * application/json - Used for sending JSON-encoded data
                * application/x-www-form-urlencoded - The default for HTML forms.
                  Data is sent as key-value pairs in the body of the request, similar to query parameters.
                * multipart/form-data - Used for file uploads or when a form includes non-ASCII characters

        Returns:
            dict:
                The request header values.

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
        json_data: dict | None = None,
        files: dict | None = None,
        timeout: int | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        retry_forever: bool = False,
    ) -> dict | None:
        """Call an PHT REST API in a safe way.

        Args:
            url (str):
                The URL to send the request to.
            method (str, optional):
                HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional):
                Request Headers. Defaults to None.
            data (dict | None, optional):
                Request payload. Defaults to None.
            json_data (dict | None, optional):
                Request payload. Defaults to None.
            files (dict | None, optional):
                Dictionary of {"name": file-tuple} for multipart encoding upload.
                The file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            timeout (int | None, optional):
                Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed REST call.
                If False, then only a warning is logged. Defaults to True.
            failure_message (str, optional):
                Specific error message. Defaults to "".
            success_message (str, optional):
                Specific success message. Defaults to "".
            max_retries (int, optional):
                How many retries on Connection errors? Default is REQUEST_MAX_RETRIES.
            retry_forever (bool, optional):
                Eventually wait forever - without timeout. Defaults to False.

        Returns:
            dict | None:
                Response of PHT REST API or None in case of an error.

        """

        retries = 0
        while True:
            try:
                response = self._session.request(
                    method=method,
                    url=url,
                    data=data,
                    json=json_data,
                    files=files,
                    headers=headers,
                    timeout=timeout,
                )

                if response.ok:
                    if success_message:
                        self.logger.debug(success_message)
                    return self.parse_request_response(response)
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    self.logger.debug("Session has expired - try to re-authenticate...")
                    self.authenticate()
                    retries += 1
                else:
                    # Handle plain HTML responses to not pollute the logs
                    content_type = response.headers.get("content-type", None)
                    response_text = "HTML content (see debug log)" if content_type == "text/html" else response.text

                    if show_error:
                        self.logger.error(
                            "%s; status -> %s; error -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )
                    else:
                        self.logger.warning(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )

                    if content_type == "text/html":
                        self.logger.debug(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
                            response.text,
                        )

                    return None
            except requests.exceptions.Timeout:
                if retries <= max_retries:
                    self.logger.warning(
                        "Request timed out. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    self.logger.error(
                        "%s; timeout error,",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                        self.logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                    else:
                        return None
            except requests.exceptions.ConnectionError:
                if retries <= max_retries:
                    self.logger.warning(
                        "Connection error. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    self.logger.error(
                        "%s; connection error.",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                        self.logger.warning("Turn timeouts off and wait forever...")
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
        """Convert the request response (JSon) to a Python list in a safe way that also handles exceptions.

        It first tries to load the response.text via json.loads() that produces
        a dict output. Only if response.text is not set or is empty it just converts
        the response_object to a dict using the vars() built-in method.

        Args:
            response_object (object):
                This is reponse object delivered by the request call.
            additional_error_message (str, optional):
                Used to provide a more specific error message.
            show_error (bool):
                If True, write an error to the log file.
                If False, write a warning to the log file.

        Returns:
            list: response information or None in case of an error

        """

        if not response_object:
            return None

        try:
            list_object = json.loads(response_object.text) if response_object.text else vars(response_object)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSON. {}; error -> {}".format(
                    additional_error_message,
                    exception,
                )
            else:
                message = "Cannot decode response as JSON; error -> {}".format(
                    exception,
                )
            if show_error:
                self.logger.error(message)
            else:
                self.logger.warning(message)
            return None
        else:
            return list_object

    # end method definition

    def authenticate(self) -> HTTPBasicAuth | None:
        """Authenticate at PHT with basic authentication.

        Returns:
            str | None:
                Session authorization string.

        """

        self._session.headers.update(self.request_header())

        username = self.config()["username"]
        password = self.config()["password"]
        if not self._session:
            self._session = requests.Session()
        self._session.auth = HTTPBasicAuth(username, password)

        return self._session.auth

    # end method definition

    def get_attributes(self) -> list | None:
        """Get a list of all product attributes (schema) of PHT.

        Returns:
            list | None: list of product attributes

        Example:
            [
                {
                    'id': 28,
                    'uuid': '43ba5852-eb83-11ed-a752-00505682262c',
                    'name': 'UBM SCM Migration JIRA/ValueEdge',
                    'description': 'Identifies the Issue to track work for the SCM migration for this project.',
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
        """Get the list of PHT Business Units.

        Returns:
            list | None:
                The list of the known business units.

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
        """Get the list of PHT product families (LoBs).

        Returns:
            list | None:
                A list of the known product families.

        """

        request_header = self.request_header()
        request_url = self.config()["productFamilyUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get PHT product families",
        )

    # end method definition

    def get_products(self) -> list | None:
        """Get the list of PHT products.

        Returns:
            list | None:
                A list of the known products.

        """

        request_header = self.request_header()
        request_url = self.config()["productUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get PHT products",
        )

    # end method definition

    def get_products_filtered(
        self,
        filter_definition: dict | None = None,
    ) -> list | None:
        """Get a list of filtered PHT products.

        Args:
            filter_definition (dict | None, optional):
                A dictionary of filter conditions. Default is None (no filter).
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
                    statuses: ["ACTIVE"],
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
            json_data=request_data,
            timeout=None,
            failure_message="Failed to get filtered PHT products",
        )

    # end method definition

    def get_product(self, sync_id: str) -> dict | None:
        """Get a specific product in PHT.

        Args:
            sync_id (str): Unique ID of the PHT product.

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
                sync_id,
            ),
        )

    # end method definition

    def search_products(
        self,
        query: str,
        business_unit: str | None = None,
        family: str | None = None,
    ) -> list | None:
        """Search for specific product in PHT by the product name, business unit or product family (or a combination).

        Args:
            query (str):
                Query to search for specific products.
            business_unit (str | None, optional):
                Used to focus the search on a specific Business Unit.
            family (str | None, optional):
                Used to focus the search on a specific product family (Line of Business)

        Returns:
            list | None:
                Search term matches any part of the component name.

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
                query,
            ),
        )

    # end method definition

    def get_master_products(self) -> list | None:
        """Get the list of PHT master products.

        Returns:
            list | None:
                A list of the known master products.

        """

        request_header = self.request_header()
        request_url = self.config()["masterProductUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get PHT master products",
        )

    # end method definition

    def get_master_products_filtered(
        self,
        filter_definition: dict | None = None,
    ) -> list | None:
        """Get a list of filtered PHT master products.

        Args:
            filter_definition (dict | None, optional):
                A dictionary of filter conditions.
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
            list | None: List of matching products.

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
            json_data=request_data,
            timeout=None,
            failure_message="Failed to get filtered PHT master products",
        )

    # end method definition

    def get_master_product(self, sync_id: str) -> dict | None:
        """Get a specific product in PHT.

        Args:
            sync_id (str): Unique PHT ID of the master product.

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
            failure_message="Failed to retrieve PHT product with sync ID -> {}".format(
                sync_id,
            ),
        )

    # end method definition

    def get_teams(self) -> list | None:
        """Get a list of all teams in PHT.

        Returns:
            list | None: list of PHT teams

        """

        request_header = self.request_header()
        request_url = self.config()["teamUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT teams",
        )

    # end method definition

    def get_team(self, team_id: str) -> dict | None:
        """Get a specific team in PHT.

        Args:
            team_id (str): Unique PHT ID of the team.

        Returns:
            dict | None: Details of the PHT team.

        """

        request_header = self.request_header()
        request_url = self.config()["teamUrl"] + "/" + str(team_id)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT team with ID -> {}".format(team_id),
        )

    # end method definition

    def get_components(self) -> list:
        """Get a list of all components in PHT.

        Returns:
            list: list of PHT components

        Example:
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
            failure_message="Failed to retrieve PHT components",
        )

    # end method definition

    def get_components_filtered(
        self,
        filter_definition: dict | None = None,
    ) -> list | None:
        """Get a list of filtered PHT components.

        Args:
            filter_definition (dict | None, optional):
                A dictionary of filter conditions.
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
            json_data=request_data,
            timeout=None,
            failure_message="Failed to get filtered PHT components",
        )

    # end method definition

    def get_component(self, sync_id: str) -> dict | None:
        """Get a specific component in PHT.

        Args:
            sync_id (str):
                Unique PHT ID of the component.

        Returns:
            dict | None:
                Details of the PHT component. None in case of an error.

        """

        request_header = self.request_header()
        request_url = self.config()["componentUrl"] + "/" + str(sync_id)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT component with sync ID -> {}!".format(
                sync_id,
            ),
        )

    # end method definition

    def search_components(self, query: str) -> list | None:
        """Search for specific components in PHT by the component name.

        Args:
            query (str): Search term to match any part of the component name.

        Returns:
            list | None: List of matching components.

        """

        request_header = self.request_header()
        request_url = self.config()["componentSearchUrl"] + "?q=" + query

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve PHT components matching -> {}".format(
                query,
            ),
        )

    # end method definition

    def load_business_units(self, business_unit_list: list | None = None) -> bool:
        """Load business units into a data frame in the self._data object.

        Args:
            business_unit_list (list, optional):
                List of business units - if already avaiable. Defaults to None.
                If None, then the list of all business units is created on-the-fly.

        Returns:
            bool:
                True if successful, False otherwise.

        """

        if not business_unit_list:
            self.logger.info("Load PHT business unit list...")
            # First, get the list of all products:
            business_unit_list = self.get_business_units()
            if business_unit_list:
                self.logger.info(
                    "Completed loading of -> %s PHT business units",
                    str(len(business_unit_list)),
                )
            else:
                self.logger.error("Failed to load PHT business units!")
                return False

        # Put the business unit list in an initial data frame.
        # This makes it easy to filter with powerful Pandas capabilities:
        self._data = Data(business_unit_list, logger=self.logger)

        # Filter based on black list for business units:
        if self._business_unit_exclusions:
            self.logger.info("Found PHT business unit exclusions...")
            condition = [
                {
                    "field": "name",
                    "value": self._business_unit_exclusions,
                    "equal": False,
                },
            ]
            self._data.filter(conditions=condition)

        # Filter based on white list for business units:
        if self._business_unit_inclusions:
            self.logger.info("Found PHT business unit inclusions...")
            condition = [
                {"field": "name", "value": self._business_unit_inclusions},
            ]
            self._data.filter(conditions=condition)

        return bool(self._data)

    # end method definition

    def load_product_families(self, product_family_list: list | None = None, append: bool = False) -> bool:
        """Load product families (LoBs) into a data frame in the self._data object.

        Args:
            product_family_list (list, optional):
                List of product families (LoBs) - if already avaiable. Defaults to None.
                If None, then the list of all product families is created on-the-fly.
            append (bool):
                Whether or not the product families should be added to an existing data frame
                or if the data frame should be reset with the product family data only.
                Default is False (drop existing data rows).

        Returns:
            bool:
                True if successful, False otherwise.

        """

        if not product_family_list:
            self.logger.info("Load PHT product family (LoB) list...")
            # First, get the list of all products:
            product_family_list = self.get_product_families()
            if product_family_list:
                self.logger.info(
                    "Completed loading of -> %s PHT product families (LoBs)",
                    str(len(product_family_list)),
                )
            else:
                self.logger.error("Failed to load PHT product families!")
                return False

        # Put the product family (LoB) list in an initial data frame.
        # This makes it easy to filter with powerful Pandas capabilities:
        data = Data(product_family_list, logger=self.logger)

        # Filter based on black list for business units:
        if self._business_unit_exclusions:
            self.logger.info("Found PHT business unit exclusions...")
            condition = [
                {
                    "field": "businessUnit.name",
                    "value": self._business_unit_exclusions,
                    "equal": False,
                },
            ]
            data.filter(conditions=condition)

        # Filter based on white list for business units:
        if self._business_unit_inclusions:
            self.logger.info("Found PHT business unit inclusions...")
            condition = [
                {"field": "businessUnit.name", "value": self._business_unit_inclusions},
            ]
            data.filter(conditions=condition)

        if self.get_data() and not data.get_data_frame().empty and append:
            self.get_data().append(add_data=data)
        else:
            self._data = data

        return bool(self._data)

    # end method definition

    def load_products(
        self,
        product_list: list | None = None,
        append: bool = False,
        attributes_to_extract: list | None = None,
    ) -> bool:
        """Load products into a data frame in the self._data object.

        The data frame has these columns:
            "syncId"
            "id"
            "name"
            "shortCode"
            "family"
            "businessUnit"
            "familySyncId"
            "businessUnitSyncId"
            "manager"
            "developmentManager"
            "status"
            "category"
            "attributes"

        Args:
            product_list (list, optional):
                List of products - if already avaiable. Defaults to None.
                If None, then the list of all products is created on-the-fly.
            append (bool):
                Whether or not the products should be added to an existing data frame
                or if the data frame should be reset with the product data only.
                Default is False (drop existing data rows).
            attributes_to_extract (list):
                A list of attributes names that should be extracted for the PHT
                "attributes" data structure inside product.

        Returns:
            bool:
                True if successful, False otherwise.

        """

        if not product_list:
            self.logger.info("Load PHT product list...")
            # First, get the list of all products:
            product_list = self.get_products()
            if product_list:
                self.logger.info(
                    "Completed loading of -> %s PHT products",
                    str(len(product_list)),
                )
            else:
                self.logger.error("Failed to load PHT products!")
                return False

        attribute_columns = []

        for product in product_list:
            product_family = product["productFamily"]
            business_unit = product_family["businessUnit"]
            category = product.get("productCategory")

            product["businessUnitSyncId"] = business_unit["syncId"]
            product["familySyncId"] = product_family["syncId"]
            if category:
                product["category"] = category["name"]

            attributes = product.get("attributes")
            # Does this product have attributes and do we want to extract any?
            if attributes and attributes_to_extract:
                for attribute in attributes:
                    if attribute.get("name") in attributes_to_extract:
                        # We fist check if there's a text value
                        value = None
                        value = attribute.get("textAttributeValue")
                        # If we don't have a text value we try to get a list value:
                        if not value and attribute.get("listAttributeValue"):
                            value = attribute.get("listAttributeValue")["name"]
                        # Create a new key / value pait with the extracted attribute and its value:
                        product[attribute.get("name")] = value
                        # We keep the attribute name as a column below:
                        if attribute.get("name") not in attribute_columns:
                            attribute_columns.append(attribute.get("name"))

        # Put the product list in an initial data frame.
        # This makes it easy to filter with powerful Pandas capabilities:
        data = Data(product_list, logger=self.logger)

        data.keep_columns(
            column_names=[
                "syncId",
                "id",
                "name",
                "shortCode",
                "family",
                "businessUnit",
                "familySyncId",
                "businessUnitSyncId",
                "manager",
                "developmentManager",
                "status",
                "category",
                "attributes",
                "comment",
            ]
            + attribute_columns,
        )
        # Filter based on black list for Business Units:
        if self._business_unit_exclusions:
            self.logger.info("Found PHT business unit exclusions...")
            condition = [
                {
                    "field": "businessUnit",
                    "value": self._business_unit_exclusions,
                    "equal": False,
                },
            ]
            data.filter(conditions=condition)

        # Filter based on white list for Business Units:
        if self._business_unit_inclusions:
            self.logger.info("Found PHT business unit inclusions...")
            condition = [
                {"field": "businessUnit", "value": self._business_unit_inclusions},
            ]
            data.filter(conditions=condition)

        # Filter based on black list for products:
        if self._product_exclusions:
            self.logger.info("Found PHT product exclusions...")
            condition = [
                {"field": "name", "value": self._product_exclusions, "equal": False},
            ]
            data.filter(conditions=condition)

        # Filter based on white list for products:
        if self._product_inclusions:
            self.logger.info("Found PHT product inclusions...")
            condition = [{"field": "name", "value": self._product_inclusions}]
            data.filter(conditions=condition)

        # Filter based on black list for product categories:
        if self._product_category_exclusions:
            self.logger.info("Found PHT product category exclusions...")
            condition = [
                {
                    "field": "category",
                    "value": self._product_category_exclusions,
                    "equal": False,
                },
            ]
            data.filter(conditions=condition)

        # Filter based on white list for product categories:
        if self._product_category_inclusions:
            self.logger.info("Found PHT product category inclusions...")
            condition = [
                {
                    "field": "category",
                    "value": self._product_category_inclusions,
                },
            ]
            data.filter(conditions=condition)

        # Filter based on product status exclusions:
        if self._product_status_exclusions:
            self.logger.info("Found PHT product status exclusions...")
            condition = [
                {
                    "field": "status",
                    "value": self._product_status_exclusions,
                    "equal": False,
                },
            ]
            data.filter(conditions=condition)

        # Filter based on product status inclusions:
        if self._product_status_inclusions:
            self.logger.info("Found PHT product status inclusions...")
            condition = [
                {
                    "field": "status",
                    "value": self._product_status_inclusions,
                    "equal": True,
                },
            ]
            data.filter(conditions=condition)

        if self.get_data() and not data.get_data_frame().empty and append:
            self.get_data().append(data)
        else:
            self._data = data

        return bool(self._data)

    # end method definition

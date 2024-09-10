"""
SuccessFactors Module to interact with the SuccessFactors API

See: 
https://community.sap.com/t5/enterprise-resource-planning-blogs-by-members/how-to-initiate-an-oauth-connection-to-successfactors-employee-central/ba-p/13332388 
https://help.sap.com/docs/SAP_SUCCESSFACTORS_PLATFORM/d599f15995d348a1b45ba5603e2aba9b/78b1d8aac783455684a7de7a8a5b0c04.html 

Class: SuccessFactors
Methods:

__init__ : class initializer
config : Returns config data set
credentials: Returns the token data
idp_data: Return the IDP data used to request the SAML assertion
request_header: Returns the request header for SuccessFactors API calls
parse_request_response: Parse the REST API responses and convert
                        them to Python dict in a safe way
exist_result_item: Check if an dict item is in the response
                   of the SuccessFactors API call
get_result_value: Check if a defined value (based on a key) is in the SuccessFactors API response

get_saml_assertion: Get SAML Assertion for SuccessFactors authentication
authenticate : Authenticates at SuccessFactors API

get_country: Get information for a Country / Countries
get_user: Get a SuccessFactors user based on its ID.
get_user_account: Get information for a SuccessFactors User Account
update_user: Update user data. E.g. update the user password or email.
get_employee: Get a list of employee(s) matching given criterias.
get_entities_metadata: Get the schema (metadata) for a list of entities
                       (list can be empty to get it for all)
get_entity_metadata: Get the schema (metadata) for an entity
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import time
import urllib.parse
import requests

import xmltodict

logger = logging.getLogger("pyxecm.customizer.sucessfactors")

request_login_headers = {
    "Content-Type": "application/x-www-form-urlencoded",  # "application/json",
    "Accept": "application/json",
}

REQUEST_TIMEOUT = 60
REQUEST_MAX_RETRIES = 5
REQUEST_RETRY_DELAY = 60

class SuccessFactors(object):
    """Used to retrieve and automate stettings in SuccessFactors."""

    _config: dict
    _access_token = None
    _assertion = None

    def __init__(
        self,
        base_url: str,
        as_url: str,
        client_id: str,
        client_secret: str,
        username: str = "",
        password: str = "",
        company_id: str = "",
        authorization_url: str = "",
    ):
        """Initialize the SuccessFactors object

        Args:
            base_url (str): base URL of the SuccessFactors tenant
            authorization_url (str): authorization URL of the SuccessFactors tenant, typically ending with "/services/oauth2/token"
            client_id (str): SuccessFactors Client ID
            client_secret (str): SuccessFactors Client Secret
            username (str): user name in SuccessFactors
            password (str): password of the user
            authorization_url (str, optional): URL for SuccessFactors login. If not given it will be constructed with default values
                                               using base_url
        """

        successfactors_config = {}

        # this class assumes that the base URL is provided without
        # a trailing "/". Otherwise the trailing slash is removed.
        if base_url.endswith("/"):
            base_url = base_url[:-1]

        # Set the authentication endpoints and credentials
        successfactors_config["baseUrl"] = base_url
        successfactors_config["asUrl"] = as_url
        successfactors_config["clientId"] = client_id
        successfactors_config["clientSecret"] = client_secret
        successfactors_config["username"] = username.split("@")[
            0
        ]  # we don't want the company ID in the user name
        successfactors_config["password"] = password
        if company_id:
            successfactors_config["companyId"] = company_id
        elif "@" in username:
            # if the company ID is not provided as a parameter
            # we check if it is included in the username:
            company_id = username.split("@")[1]
            successfactors_config["companyId"] = company_id
        if authorization_url:
            successfactors_config["authenticationUrl"] = authorization_url
        else:
            successfactors_config["authenticationUrl"] = (
                successfactors_config["baseUrl"] + "/oauth/token"
            )

        successfactors_config["idpUrl"] = (
            successfactors_config["baseUrl"] + "/oauth/idp"
        )

        if not username:
            # Set the data for the token request
            successfactors_config["authenticationData"] = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                # "username": successfactors_config["username"],
                # "password": password,
            }
        else:
            # Set the data for the token request
            successfactors_config["authenticationData"] = {
                #                "grant_type": "password",
                "grant_type": "urn:ietf:params:oauth:grant-type:saml2-bearer",
                "company_id": successfactors_config["companyId"],
                "username": successfactors_config["username"],
                "password": password,
                "client_id": client_id,
                "client_secret": client_secret,
            }

        successfactors_config["idpData"] = {
            "client_id": client_id,
            "user_id": successfactors_config["username"],
            #            "use_email": True,
            "token_url": successfactors_config["authenticationUrl"],
            "private_key": client_secret,
        }

        self._config = successfactors_config

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
            dict: dictionary with login credentials for SuccessFactors
        """
        return self.config()["authenticationData"]

    # end method definition

    def idp_data(self) -> dict:
        """Return the IDP data used to request the SAML assertion

        Returns:
            dict: dictionary with IDP data for SuccessFactors
        """
        return self.config()["idpData"]

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
            "Accept": content_type,
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
        """Check existence of key / value pair in the response properties of an SuccessFactors API call.

        Args:
            response (dict): REST response from an SuccessFactors API call
            key (str): property name (key)
            value (str): value to find in the item with the matching key
        Returns:
            bool: True if the value was found, False otherwise
        """

        if not response:
            return False

        if "d" in response:
            data = response["d"]
            if not key in data:
                return False
            if value == data[key]:
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
        """Get value of a result property with a given key of an SuccessFactors API call.

        Args:
            response (dict): REST response from an SuccessFactors REST Call
            key (str): property name (key)
            index (int, optional): Index to use (1st element has index 0).
                                   Defaults to 0.
        Returns:
            str: value for the key, None otherwise
        """

        if not response or not "d" in response:
            return None

        data = response["d"]

        # list response types are wrapped in a "results" element
        # which is of type list
        if "results" in data:
            results = data["results"]
            if not results or not isinstance(results, list):
                return None
            try:
                value = results[index][key]
            except IndexError as e:
                logger.error(
                    "Index error with index -> %s and key -> %s: %s",
                    str(index),
                    key,
                    str(e),
                )
                return None
            except KeyError as e:
                logger.error(
                    "Key error with index -> %s and key -> %s: %s",
                    str(index),
                    key,
                    str(e),
                )
                return None
        else:  # simple response - try to find key in response directly:
            if not key in data:
                return None
            value = data[key]

        return value

    # end method definition

    def get_saml_assertion(self) -> str | None:
        """Get SAML Assertion for SuccessFactors authentication.

        Args:
            None
        Returns:
            str: Assertion. Also stores access token in self._assertion. None in case of error
        """

        request_url = self.config()["idpUrl"]

        #        request_header = request_login_headers

        logger.debug("Requesting SuccessFactors SAML Assertion from -> %s", request_url)

        idp_post_body = self.config()["idpData"]

        response = None
        self._assertion = None

        try:
            response = requests.post(
                request_url,
                data=idp_post_body,
                #                headers=request_header,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.ConnectionError as exception:
            logger.error(
                "Unable to get SAML assertion from -> %s : %s",
                self.config()["idpUrl"],
                exception,
            )
            return None

        if response.ok:
            assertion = response.text
            self._assertion = assertion
            logger.debug("Assertion -> %s", self._assertion)
            return assertion

        logger.error(
            "Failed to request an SuccessFactors SAML Assertion; error -> %s",
            response.text,
        )
        return None

    # end method definition

    def authenticate(self, revalidate: bool = False) -> str | None:
        """Authenticate at SuccessFactors with client ID and client secret.

        Args:
            revalidate (bool, optional): determinse if a re-athentication is enforced
                                         (e.g. if session has timed out with 401 error)
        Returns:
            str: Access token. Also stores access token in self._access_token. None in case of error
        """

        if not self._assertion:
            self._assertion = self.get_saml_assertion()

        # Already authenticated and session still valid?
        if self._access_token and not revalidate:
            logger.debug(
                "Session still valid - return existing access token -> %s",
                str(self._access_token),
            )
            return self._access_token

        request_url = self.config()["authenticationUrl"]

        #        request_header = request_login_headers

        logger.debug("Requesting SuccessFactors Access Token from -> %s", request_url)

        authenticate_post_body = self.credentials()
        authenticate_post_body["assertion"] = self._assertion

        response = None
        self._access_token = None

        try:
            response = requests.post(
                request_url,
                data=authenticate_post_body,
                #                headers=request_header,
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
            if not authenticate_dict or not "access_token" in authenticate_dict:
                return None
            # Store authentication access_token:
            self._access_token = authenticate_dict["access_token"]
            logger.debug("Access Token -> %s", self._access_token)
        else:
            logger.error(
                "Failed to request an SuccessFactors Access Token; error -> %s",
                response.text,
            )
            return None

        return self._access_token

    # end method definition

    def get_country(self, code: str = "") -> dict | None:
        """Get information for a Country / Countries

        Args:
            code (str): 3 character code for contry selection, like "USA"

        Returns:
            dict | None: Country details

            Example return data in "d" dictionary:

            {
                '__metadata': {
                    'uri': "https://apisalesdemo2.successfactors.eu/odata/v2/UserAccount('twalker')",
                    'type': 'SFOData.UserAccount'
                },
                'username': 'twalker',
                'lastModifiedDateTime': '/Date(1692701804000+0000)/',
                'accountUuid': '5c7390e0-d9d2-e348-1700-2b02b3a61aa5',
                'createdDateTime': '/Date(1420745485000+0000)/',
                'timeZone': 'US/Eastern',
                'lastInactivationDateTime': None,
                'accountIsLocked': 'FALSE',
                'accountStatus': 'ACTIVE',
                'defaultLocale': 'en_US',
                'lastLoginFailedDateTime': None,
                'accountId': '90',
                'sapGlobalUserId': None,
                'personIdExternal': '82094',
                'userType': 'employee',
                'email': 'twalker@m365x41497014.onmicrosoft.com',
                'user': {'__deferred': {...}}
            }
        """

        if not self._access_token:
            self.authenticate()

        if code:
            request_url = self.config()["asUrl"] + "Country(code='{}')".format(
                code
            )  # ,effectiveStartDate=datetime'1900-01-01T00:00:00'
        else:
            request_url = self.config()["asUrl"] + "Country"

        request_header = self.request_header()

        response = requests.get(
            request_url, headers=request_header, timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            return self.parse_request_response(response)
        else:
            logger.error(
                "Failed to retrieve country data; status -> %s; error -> %s",
                response.status_code,
                response.text,
            )
            return None

    # end method definition

    def get_user(
        self,
        user_id: str = "",  # this is NOT the username but really an ID like 106020
        field_name: str = "",
        field_value: str = "",
        field_operation: str = "eq",
        max_results: int = 1,
    ) -> dict | None:
        """Get information for a User Account
           Inactive users are not returned by default. To query inactive users,
           you can explicitly include the status in a $filter or use a key predicate.
           If you want to query all users, use query option $filter=status in 't','f','T','F','e','d'.

        Args:
            user_id (str): login name of the user (e.g. "twalker")

        Returns:
            dict | None: User Account details

            Example return data in "d" dictionary:

            {
                '__metadata': {
                    'uri': "https://apisalesdemo2.successfactors.eu/odata/v2/User('106020')",
                    'type': 'SFOData.User'
                },
                'userId': '106020',
                'salaryBudgetFinalSalaryPercentage': None,
                'dateOfCurrentPosition': '/Date(1388534400000)/',
                'matrix1Label': None,
                'salary': '79860.0',
                'objective': '0.0',
                'ssn': None,
                'state': 'New South Wales',
                'issueComments': None,
                'timeZone': 'Australia/Sydney',
                'defaultLocale': 'en_US',
                'nationality': None,
                'salaryBudgetLumpsumPercentage': None,
                'sysCostOfSource': None,
                'ethnicity': None,
                'displayName': 'Mark Burke',
                'payGrade': 'GR-06',
                'nickname': None,
                'email': 'Mark.Burke@bestrunsap.com',
                'salaryBudgetExtra2Percentage': None,
                'stockBudgetOther1Amount': None,
                'raiseProrating': None,
                'sysStartingSalary': None,
                'finalJobCode': None,
                'lumpsum2Target': None,
                'stockBudgetOptionAmount': None,
                'country': 'Australia',
                'lastModifiedDateTime': '/Date(1689005658000+0000)/',
                'stockBudgetStockAmount': None,
                'sciLastModified': None,
                'criticalTalentComments': None,
                'homePhone': None,
                'veteranSeparated': False,
                'stockBudgetOther2Amount': None,
                'firstName': 'Mark',
                'stockBudgetUnitAmount': None,
                'salutation': '10808',
                'impactOfLoss': None,
                'benchStrength': None,
                'sysSource': None,
                'futureLeader': None,
                'title': 'HR Business Partner',
                'meritEffectiveDate': None,
                'veteranProtected': False,
                'lumpsumTarget': None,
                'employeeClass': 'Active',
                'hireDate': '/Date(1388534400000)/',
                'matrix2Label': None, 'salaryLocal': None,
                'citizenship': None,
                'reasonForLeaving': None,
                'riskOfLoss': None,
                'location': 'Sydney (8510-0001)',
                'reloComments': None,
                'username': 'mburke',
                'serviceDate': None,
                'reviewFreq': None,
                'salaryBudgetTotalRaisePercentage': None,
                ...
            }
        """

        if not self._access_token:
            self.authenticate()

        request_url = self.config()["asUrl"] + "User"
        if user_id:
            # querying a user by key predicate:
            request_url += "('{}')".format(user_id)

        # Add query parameters (these are NOT passed via JSon body!)
        query = {}
        if field_name and field_value:
            query["$filter"] = "{} {} {}".format(
                field_name, field_operation, field_value
            )
        if max_results > 0:
            query["$top"] = max_results
        encoded_query = urllib.parse.urlencode(query, doseq=True)
        if query:
            request_url += "?" + encoded_query

        request_header = self.request_header()

        response = requests.get(
            request_url, headers=request_header, timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            return self.parse_request_response(response)
        else:
            logger.error(
                "Failed to retrieve user data; status -> %s; error -> %s",
                response.status_code,
                response.text,
            )
            return None

    # end method definition

    def get_user_account(self, username: str) -> dict | None:
        """Get information for a SuccessFactors User Account
           Inactive users are not returned by default. To query inactive users,
           you can explicitly include the status in a $filter or use a key predicate.
           If you want to query all users, use query option $filter=status in 't','f','T','F','e','d'.

        Args:
            username (str): login name of the user (e.g. "twalker")

        Returns:
            dict | None: User Account details

            Example return data in "d" dictionary:

            {
                '__metadata': {
                    'uri': "https://apisalesdemo2.successfactors.eu/odata/v2/UserAccount('twalker')",
                    'type': 'SFOData.UserAccount'
                },
                'username': 'twalker',
                'lastModifiedDateTime': '/Date(1692701804000+0000)/',
                'accountUuid': '5c7390e0-d9d2-e348-1700-2b02b3a61aa5',
                'createdDateTime': '/Date(1420745485000+0000)/',
                'timeZone': 'US/Eastern',
                'lastInactivationDateTime': None,
                'accountIsLocked': 'FALSE',
                'accountStatus': 'ACTIVE',
                'defaultLocale': 'en_US',
                'lastLoginFailedDateTime': None,
                'accountId': '90',
                'sapGlobalUserId': None,
                'personIdExternal': '82094',
                'userType': 'employee',
                'email': 'twalker@m365x41497014.onmicrosoft.com',
                'user': {'__deferred': {...}}
            }
        """

        if not self._access_token:
            self.authenticate()

        request_url = self.config()["asUrl"] + "UserAccount('{}')".format(username)

        request_header = self.request_header()

        retries = 0

        while True:
            try:
                response = requests.get(
                    request_url, headers=request_header, timeout=REQUEST_TIMEOUT
                )
                response.raise_for_status()  # This will raise an HTTPError for bad responses
                return self.parse_request_response(response)
            except requests.exceptions.HTTPError as http_err:
                logger.error(
                    "Failed to retrieve user data from SuccessFactors; status -> %s; error -> %s",
                    response.status_code,
                    str(http_err),
                )
            except requests.exceptions.Timeout:
                logger.warning(
                    "Failed to retrieve user data from SuccessFactors. The request timed out.",
                )
            except requests.exceptions.ConnectionError as conn_err:
                logger.error(
                    "Cannot connect to SuccessFactors to retrieve user data; status -> %s; error -> %s",
                    response.status_code,
                    str(conn_err),
                )
            except requests.exceptions.RequestException as req_err:
                logger.error(
                    "Failed to retrieve user data from SuccessFactors; status -> %s; error -> %s",
                    response.status_code,
                    str(req_err),
                )
            retries += 1
            if retries <= REQUEST_MAX_RETRIES:
                logger.info("Retrying in %s seconds...", str(REQUEST_RETRY_DELAY))
                time.sleep(retries * REQUEST_RETRY_DELAY)
            else:
                break

        return None

    # end method definition

    def update_user(
        self,
        user_id: str,  # this is NOT the username but really an ID like 106020
        update_data: dict,
    ) -> dict:
        """Update user data. E.g. update the user password or email.
           See: https://help.sap.com/docs/SAP_SUCCESSFACTORS_PLATFORM/d599f15995d348a1b45ba5603e2aba9b/47c39724e7654b99a6be2f71fce1c50b.html?locale=en-US

        Args:
            user_id (str): ID of the user (e.g. 106020)
            update_data (dict): Update data
        Returns:
            dict: Request response or None if an error occured.
        """

        if not self._access_token:
            self.authenticate()

        request_url = self.config()["asUrl"] + "User('{}')".format(user_id)

        request_header = self.request_header()
        # We need to use a special MERGE header to tell
        # SuccessFactors to only change the new / provided fields:
        request_header["X-HTTP-METHOD"] = "MERGE"

        response = requests.post(
            request_url,
            headers=request_header,
            json=update_data,
            timeout=REQUEST_TIMEOUT,
        )
        if response.ok:
            logger.debug("User with ID -> %s updated successfully.", user_id)
            return self.parse_request_response(response)
        else:
            logger.error(
                "Failed to update user with ID -> %s; status -> %s; error -> %s",
                user_id,
                response.status_code,
                response.text,
            )
            return None

    # end method definition

    def get_employee(
        self,
        entity: str = "PerPerson",
        field_name: str = "",
        field_value: str = "",
        field_operation: str = "eq",
        max_results: int = 1,
    ) -> dict | None:
        """Get a list of employee(s) matching given criterias.

        Args:
            entity (str, optional): Entity type to query. Examples are "PerPerson" (default),
                                    "PerPersonal", "PerEmail", "PersonKey", ...
            field_name (str): Field to search in. E.g. personIdExternal, firstName, lastName,
                              fullName, email, dateOfBirth, gender, nationality, maritalStatus,
                              employeeId
            field_value (str): Value to match in the Field

        Returns:
            dict | None: Dictionary with the SuccessFactors object data or None in case the request failed.

            Example result values for "PerPerson" inside the "d" structure:

            "results": [
                {
                    '__metadata': {...},
                    'personIdExternal': '109031',
                    'lastModifiedDateTime': '/Date(1442346839000+0000)/',
                    'lastModifiedBy': 'admindlr',
                    'createdDateTime': '/Date(1442346265000+0000)/',
                    'dateOfBirth': '/Date(-501206400000)/',
                    'perPersonUuid': '0378B0E6F41444EBB90345B56D537D3D',
                    'createdOn': '/Date(1442353465000)/',
                    'lastModifiedOn': '/Date(1442354039000)/',
                    'countryOfBirth': 'RUS',
                    'createdBy': 'admindlr',
                    'regionOfBirth': None,
                    'personId': '771',
                    'personalInfoNav': {...},
                    'emergencyContactNav': {...},
                    'secondaryAssignmentsNav': {...},
                    'personEmpTerminationInfoNav': {...},
                    'phoneNav': {...},
                    'employmentNav': {...},
                    ...
                }
            ]

            Example result values for "PerPersonal" inside the "d" structure:

            "results": [
                {
                    '__metadata': {
                        'uri': "https://apisalesdemo2.successfactors.eu/odata/v2/PerPersonal(personIdExternal='108729',startDate=datetime'2017-03-13T00:00:00')",
                        'type': 'SFOData.PerPersonal'
                    },
                    'personIdExternal': '108729',
                    'startDate': '/Date(1489363200000)/',
                    'lastModifiedDateTime': '/Date(1489442337000+0000)/',
                    'endDate': '/Date(253402214400000)/',
                    'createdDateTime': '/Date(1489442337000+0000)/',
                    'suffix': None,
                    'attachmentId': None,
                    'preferredName': 'Hillary',
                    'lastNameAlt1': None,
                    'firstName': 'Hillary',
                    'nationality': 'USA',
                    'salutation': '30085',
                    'maritalStatus': '10825',
                    'lastName': 'Lawson',
                    'gender': 'F',
                    'firstNameAlt1': None,
                    'createdOn': '/Date(1489445937000)/',
                    'middleNameAlt1': None,
                    'lastModifiedBy': '82094',
                    'lastModifiedOn': '/Date(1489445937000)/',
                    'createdBy': '82094',
                    'middleName': None,
                    'nativePreferredLang': '10249',
                    'localNavAUS': {'__deferred': {...}},
                    'localNavBGD': {'__deferred': {...}},
                    'localNavHKG': {'__deferred': {...}},
                    'localNavMYS': {'__deferred': {...}},
                    'localNavAUT': {'__deferred': {...}},
                    'localNavLKA': {'__deferred': {...}},
                    'localNavPOL': {'__deferred': {...}},
                    'localNavCZE': {'__deferred': {...}},
                    'localNavTWN': {'__deferred': {...}},
                    'localNavARE': {'__deferred': {...}},
                    'localNavARG': {'__deferred': {...}},
                    'localNavCAN': {'__deferred': {...}},
                    'localNavNOR': {'__deferred': {...}},
                    'localNavOMN': {'__deferred': {...}},
                    'localNavPER': {'__deferred': {...}},
                    'localNavSGP': {'__deferred': {...}},
                    'localNavVEN': {'__deferred': {...}},
                    'localNavZAF': {'__deferred': {...}},
                    'localNavCHL': {'__deferred': {...}},
                    'localNavCHE': {'__deferred': {...}},
                    'localNavDNK': {'__deferred': {...}},
                    'localNavGTM': {'__deferred': {...}},
                    'localNavNZL': {'__deferred': {...}},
                    'salutationNav': {'__deferred': {...}},
                    'localNavCHN': {'__deferred': {...}},
                    'localNavVNM': {'__deferred': {...}},
                    'localNavIDN': {'__deferred': {...}},
                    'localNavPRT': {'__deferred': {...}},
                    'localNavCOL': {'__deferred': {...}},
                    'localNavHUN': {'__deferred': {...}},
                    'localNavSWE': {'__deferred': {...}},
                    'localNavESP': {'__deferred': {...}},
                    'localNavUSA': {'__deferred': {...}},
                    'nativePreferredLangNav': {'__deferred': {...}},
                    'maritalStatusNav': {'__deferred': {...}}, ...}
        """

        if not self._access_token:
            self.authenticate()

        # Add query parameters (these are NOT passed via JSon body!)
        query = {}
        if field_name and field_value:
            query["$filter"] = "{} {} {}".format(
                field_name, field_operation, field_value
            )
        if max_results > 0:
            query["$top"] = max_results
        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["asUrl"] + entity
        if query:
            request_url += "?" + encoded_query

        request_header = self.request_header()

        response = requests.get(
            request_url, headers=request_header, timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            return self.parse_request_response(response)
        else:
            logger.error(
                "Failed to retrieve employee data; status -> %s; error -> %s",
                response.status_code,
                response.text,
            )
            return None

    # end method definition

    def get_entities_metadata(self, entities: list | None = None) -> dict | None:
        """Get the schema (metadata) for a list of entities (list can be empty to get it for all)
           IMPORTANT: A metadata request using $metadata returns an XML serialization of the service,
           including the entity data model (EDM) and the service operation descriptions.
           The metadata response supports only application/xml type.

        Args:
            entities (list): list of entities to deliver metadata for

        Returns:
            dict | None: Dictionary with the SuccessFactors object data or None in case the request failed.
        """

        if not self._access_token:
            self.authenticate()

        request_url = self.config()["asUrl"]
        if entities:
            request_url += "{}/".format(",".join(entities))
        request_url += "$metadata"

        request_header = self.request_header()
        request_header["Accept"] = "application/xml"

        response = requests.get(
            request_url, headers=request_header, timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            return xmltodict.parse(response.text)
        else:
            logger.error(
                "Failed to retrieve entity data; status -> %s; error -> %s",
                response.status_code,
                response.text,
            )
            return None

    # end method definition

    def get_entity_metadata(self, entity: str) -> dict | None:
        """Get the schema (metadata) for an entity

        Args:
            entity (str): entity to deliver metadata for

        Returns:
            dict | None: Dictionary with the SuccessFactors object data or None in case the request failed.
        """

        if not self._access_token:
            self.authenticate()

        if not entity:
            return None

        request_url = self.config()["asUrl"] + "Entity('{}')?$format=JSON".format(
            entity
        )

        request_header = self.request_header()

        response = requests.get(
            request_url, headers=request_header, timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            return self.parse_request_response(response)
        else:
            logger.error(
                "Failed to retrieve entity data; status -> %s; error -> %s",
                response.status_code,
                response.text,
            )
            return None

    # end method definition

    def update_user_email(
        self,
        user_id: str,  # this is NOT the username but really an ID like 106020
        email_address: str,
        email_type: int = 8448,  # 8448
    ) -> dict:
        """Update user email.
           See: https://help.sap.com/docs/SAP_SUCCESSFACTORS_PLATFORM/d599f15995d348a1b45ba5603e2aba9b/7b3daeb3d77d491bb401345eede34bb5.html?locale=en-US

        Args:
            user_id (str): ID of the user (e.g. 106020)
            email_address (str): new email address of user
            email_type (int): Type of the email. 8448 = Business
        Returns:
            dict: Request response or None if an error occured.
        """

        if not self._access_token:
            self.authenticate()

        request_url = self.config()["asUrl"] + "upsert"

        update_data = {
            "__metadata": {
                "uri": "PerEmail(emailType='{}',personIdExternal='{}')".format(
                    email_type, user_id
                ),
                "type": "SFOData.PerEmail",
            },
            "emailAddress": email_address,
        }

        request_header = self.request_header()

        response = requests.post(
            request_url,
            headers=request_header,
            json=update_data,
            timeout=REQUEST_TIMEOUT,
        )
        if response.ok:
            logger.debug(
                "Email of user with ID -> %s successfully updated to -> %s.",
                user_id,
                email_address,
            )
            return self.parse_request_response(response)
        else:
            logger.error(
                "Failed to set email of user with ID -> %s; status -> %s; error -> %s",
                user_id,
                response.status_code,
                response.text,
            )
            return None

    # end method definition

"""Synchronize AppWorks projects, publsh and create run time instances for that."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import platform
import re
import sys
import time
import uuid
from http import HTTPStatus
from importlib.metadata import version

import requests

from pyxecm.helper.xml import XML
from pyxecm.otds import OTDS

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otawp"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

REQUEST_HEADERS_XML = {
    "User-Agent": USER_AGENT,
    "Content-Type": "text/xml; charset=utf-8",
    "accept": "application/xml",
}

REQUEST_FORM_HEADERS = {
    "User-Agent": USER_AGENT,
    "accept": "application/xml;charset=utf-8",
    "Content-Type": "application/x-www-form-urlencoded",
}

REQUEST_HEADERS_JSON = {
    "User-Agent": USER_AGENT,
    "Content-Type": "application/json; charset=utf-8",
    "accept": "application/json",
}

REQUEST_TIMEOUT = 120.0
REQUEST_MAX_RETRIES = 10
REQUEST_RETRY_DELAY = 30.0
SYNC_PUBLISH_REQUEST_TIMEOUT = 600.0

default_logger = logging.getLogger(MODULE_NAME)

SOAP_FAULT_INDICATOR = "Fault"


class OTAWP:
    """Class OTAWP is used to automate settings in OpenText AppWorks Platform (OTAWP)."""

    # Only class variables or class-wide constants should be defined here:

    logger: logging.Logger = default_logger

    @classmethod
    def resource_payload(
        cls,
        org_name: str,
        username: str,
        password: str,
    ) -> dict:
        """Create data structure for OTDS resource settings we need for AppWorks.

        Args:
            org_name (str):
                The name of the organization.
            username (str):
                The user name.
            password (str):
                The password.

        Returns:
            dict:
                AppWorks specific payload.

        """

        additional_payload = {}
        additional_payload["connectorid"] = "rest"
        additional_payload["resourceType"] = "rest"
        user_attribute_mapping = [
            {
                "sourceAttr": ["oTExternalID1"],
                "destAttr": "__NAME__",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["displayname"],
                "destAttr": "DisplayName",
                "mappingFormat": "%s",
            },
            {"sourceAttr": ["mail"], "destAttr": "Email", "mappingFormat": "%s"},
            {
                "sourceAttr": ["oTTelephoneNumber"],
                "destAttr": "Telephone",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTMobile"],
                "destAttr": "Mobile",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTFacsimileTelephoneNumber"],
                "destAttr": "Fax",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTStreetAddress,l,st,postalCode,c"],
                "destAttr": "Address",
                "mappingFormat": "%s%n%s %s %s%n%s",
            },
            {
                "sourceAttr": ["oTCompany"],
                "destAttr": "Company",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["ds-pwp-account-disabled"],
                "destAttr": "AccountDisabled",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTExtraAttr9"],
                "destAttr": "IsServiceAccount",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["custom:proxyConfiguration"],
                "destAttr": "ProxyConfiguration",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["c"],
                "destAttr": "Identity-CountryOrRegion",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["gender"],
                "destAttr": "Identity-Gender",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["displayName"],
                "destAttr": "Identity-DisplayName",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTStreetAddress"],
                "destAttr": "Identity-Address",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["l"],
                "destAttr": "Identity-City",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["mail"],
                "destAttr": "Identity-Email",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["givenName"],
                "destAttr": "Identity-FirstName",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["sn"],
                "destAttr": "Identity-LastName",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["initials"],
                "destAttr": "Identity-MiddleNames",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTMobile"],
                "destAttr": "Identity-Mobile",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["postalCode"],
                "destAttr": "Identity-PostalCode",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["st"],
                "destAttr": "Identity-StateOrProvince",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["title"],
                "destAttr": "Identity-title",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["physicalDeliveryOfficeName"],
                "destAttr": "Identity-physicalDeliveryOfficeName",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTFacsimileTelephoneNumber"],
                "destAttr": "Identity-oTFacsimileTelephoneNumber",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["notes"],
                "destAttr": "Identity-notes",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTCompany"],
                "destAttr": "Identity-oTCompany",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTDepartment"],
                "destAttr": "Identity-oTDepartment",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["birthDate"],
                "destAttr": "Identity-Birthday",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["cn"],
                "destAttr": "Identity-UserName",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["Description"],
                "destAttr": "Identity-UserDescription",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["oTTelephoneNumber"],
                "destAttr": "Identity-Phone",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["displayName"],
                "destAttr": "Identity-IdentityDisplayName",
                "mappingFormat": "%s",
            },
        ]
        additional_payload["userAttributeMapping"] = user_attribute_mapping
        group_attribute_mapping = [
            {
                "sourceAttr": ["cn"],
                "destAttr": "__NAME__",
                "mappingFormat": '%js:function format(name) { return name.replace(/&/g,"-and-"); }',
            },
            {
                "sourceAttr": ["description"],
                "destAttr": "Description",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["description"],
                "destAttr": "Identity-Description",
                "mappingFormat": "%s",
            },
            {
                "sourceAttr": ["displayName"],
                "destAttr": "Identity-DisplayName",
                "mappingFormat": "%s",
            },
        ]
        additional_payload["groupAttributeMapping"] = group_attribute_mapping
        additional_payload["connectorName"] = "REST (Generic)"
        additional_payload["pcCreatePermissionAllowed"] = "true"
        additional_payload["pcModifyPermissionAllowed"] = "true"
        additional_payload["pcDeletePermissionAllowed"] = "false"
        additional_payload["connectionParamInfo"] = [
            {
                "name": "fBaseURL",
                "value": "http://appworks:8080/home/" + org_name + "/app/otdspush",
            },
            {"name": "fUsername", "value": username},
            {"name": "fPassword", "value": password},
        ]

        return additional_payload

    # end method definition

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        organization: str | None = None,
        otawp_ticket: str | None = None,
        config_map_name: str | None = None,
        license_file: str | None = None,
        product_name: str | None = None,
        product_description: str | None = None,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize OTAWP (AppWorks Platform) object.

        Args:
            protocol (str):
                Either http or https.
            hostname (str):
                The hostname of Extended ECM server to communicate with.
            port (int):
                The port number used to talk to the Extended ECM server.
            username (str | None, optional):
                The admin user name of OTAWP. Optional if otawp_ticket is provided.
            password (str | None, optional):
                The admin password of OTAWP. Optional if otawp_ticket is provided.
            organization (str | None, optional):
                The AppWorks organization. Used in LDAP strings and base URL.
            otawp_ticket (str | None, optional):
                The authentication ticket of OTAWP.
            config_map_name (str | None, optional):
                The AppWorks Kubernetes Config Map name. Defaults to None.
            license_file (str | None, optional):
                The file name and path to the license file for AppWorks. Defaults to None.
            product_name (str | None, optional):
                The product name for OTAWP used in the OTDS license. Defaults to None.
            product_description (str | None, optional):
                The product description in the OTDS license. Defaults to None.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otawp")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        otawp_config = {}

        otawp_config["hostname"] = hostname if hostname else "appworks"
        otawp_config["protocol"] = protocol if protocol else "http"
        otawp_config["port"] = port if port else 8080
        otawp_config["username"] = username if username else "sysadmin"
        otawp_config["password"] = password if password else ""
        otawp_config["organization"] = organization if organization else "system"
        otawp_config["configMapName"] = config_map_name if config_map_name else ""
        otawp_config["licenseFile"] = license_file if license_file else ""
        otawp_config["productName"] = product_name if product_name else "APPWORKS_PLATFORM"
        otawp_config["productDescription"] = (
            product_description if product_description else "OpenText Appworks Platform"
        )

        if otawp_ticket:
            self._otawp_ticket = otawp_ticket
            self._cookie = {"defaultinst_SAMLart": otawp_ticket}

        server_url = "{}://{}".format(protocol, otawp_config["hostname"])
        if str(port) not in ["80", "443"]:
            server_url += ":{}".format(port)

        otawp_config["serverUrl"] = server_url

        self._config = otawp_config
        self._cookie = None
        self._otawp_ticket = None

        self.set_organization(otawp_config["organization"])

    # end method definition

    def server_url(self) -> str:
        """Return AppWorks server information.

        Returns:
            str:
                Server configuration.

        """

        return self.config()["server"]

    # end method definition

    def set_organization(self, organization: str) -> None:
        """Set the AppWorks organization context.

        This requires to also update all URLs that are including
        the organization.

        Args:
            organization (str):
                The AppWorks organization name.

        """

        self._config["organization"] = organization

        otawp_base_url = self._config["serverUrl"] + "/home/{}".format(self._config["organization"])
        self._config["baseUrl"] = otawp_base_url

        ldap_root = "organization=o={},cn=cordys,cn=defaultInst,o=opentext.net".format(self._config["organization"])
        self._config["gatewayAuthenticationUrl"] = otawp_base_url + "/com.eibus.web.soap.Gateway.wcp?" + ldap_root

        self._config["soapGatewayUrl"] = self._config["gatewayAuthenticationUrl"] + "&defaultinst_ct=abcd"

        self._config["entityUrl"] = otawp_base_url + "/app/entityRestService/api/OpentextCaseManagement/entities"

        self._config["priorityUrl"] = self._config["entityUrl"] + "/Priority"
        self._config["priorityListUrl"] = self._config["priorityUrl"] + "/lists/PriorityList"

        self._config["customerUrl"] = self._config["entityUrl"] + "/Customer"
        self._config["customerListUrl"] = self._config["customerUrl"] + "/lists/CustomerList"

        self._config["caseTypeUrl"] = self._config["entityUrl"] + "/CaseType"
        self._config["caseTypeListUrl"] = self._config["caseTypeUrl"] + "/lists/AllCaseTypes"

        self._config["categoryUrl"] = self._config["entityUrl"] + "/Category"
        self._config["categoryListUrl"] = self._config["categoryUrl"] + "/lists/CategoryList"

        self._config["subCategoryListUrl"] = (
            self._config["categoryUrl"] + "/childEntities/SubCategory/lists/AllSubcategories"
        )

        self._config["sourceUrl"] = self._config["entityUrl"] + "/Source"
        self._config["sourceListUrl"] = self._config["sourceUrl"] + "/lists/AllSources"

        self._config["caseUrl"] = self._config["entityUrl"] + "/Case"
        self._config["caseListUrl"] = self._config["caseUrl"] + "/lists/AllCasesList"

        self.logger.info("AppWorks organization set to -> '%s'.", organization)

    # end method definition

    def base_url(self) -> str:
        """Return the base URL of AppWorks.

        Returns:
            str:
                The base URL of AppWorks Platform.

        """

        return self.config()["baseUrl"]

    # end method definition

    def license_file(self) -> str:
        """Return the AppWorks license file.

        Returns:
            str:
                The name (including path) of the AppWorks license file.

        """

        return self.config()["licenseFile"]

    # end method definition

    def product_name(self) -> str:
        """Return the AppWorks product name as used in the OTDS license.

        Returns:
            str:
                The AppWorks product name.

        """

        return self.config()["productName"]

    # end method definition

    def product_description(self) -> str:
        """Return the AppWorks product description as used in the OTDS license.

        Returns:
            str:
                The AppWorks product description.

        """

        return self.config()["productDescription"]

    # end method definition

    def hostname(self) -> str:
        """Return the AppWorks hostname.

        Returns:
            str:
                The AppWorks hostname.

        """

        return self.config()["hostname"]

    def username(self) -> str:
        """Return the AppWorks username.

        Returns:
            str:
                The AppWorks username

        """

        return self.config()["username"]

    # end method definition

    def password(self) -> str:
        """Return the AppWorks password.

        Returns:
            str:
                The AppWorks password.

        """

        return self.config()["password"]

    # end method definition

    def config_map_name(self) -> str:
        """Return AppWorks Kubernetes config map name.

        Returns:
            str:
                The Kubernetes config map name of AppWorks.

        """

        return self.config()["configMapName"]

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict: Configuration dictionary

        """

        return self._config

    # end method definition

    def cookie(self) -> dict:
        """Return the login cookie of OTAWP.

        This is set by the authenticate() method

        Returns:
            dict:
                OTAWP cookie

        """

        return self._cookie

    # end method definition

    def credentials(self) -> str:
        """Return the SOAP payload with credentials (username and password).

        Returns:
            str:
                SOAP payload with username and password.

        """

        username = self.config()["username"]
        password = self.config()["password"]

        soap_payload = f"""
        <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP:Header>
                <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    <wsse:UsernameToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                        <wsse:Username>{username}</wsse:Username>
                        <wsse:Password>{password}</wsse:Password>
                    </wsse:UsernameToken>
                    <i18n:international xmlns:i18n="http://www.w3.org/2005/09/ws-i18n">
                        <locale xmlns="http://www.w3.org/2005/09/ws-i18n">en-US</locale>
                    </i18n:international>
                </wsse:Security>
            </SOAP:Header>
            <SOAP:Body>
                <samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1">
                    <samlp:AuthenticationQuery>
                        <saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">
                            <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{username}</saml:NameIdentifier>
                        </saml:Subject>
                    </samlp:AuthenticationQuery>
                </samlp:Request>
            </SOAP:Body>
        </SOAP:Envelope>
        """

        return soap_payload

    # end method definition

    def credential_url(self) -> str:
        """Return the credentials URL of OTAWP.

        Returns:
            str:
                The AppWorks credentials URL.

        """

        return self.config()["gatewayAuthenticationUrl"]

    # end method definition

    def gateway_url(self) -> str:
        """Return SOAP gateway URL of OTAWP.

        Returns:
            str:
                The AppWorks SOAP gateway URL.

        """

        return self.config()["soapGatewayUrl"]

    # end method definition

    def get_create_priority_url(self) -> str:
        """Return create priority URL of OTAWP.

        Returns:
            str:
                The create priority URL.

        """

        return self.config()["priorityUrl"] + "?defaultinst_ct=abcd"

    # end method definition

    def get_priorities_list_url(self) -> str:
        """Get OTAWP URL to retrieve a list of all priorities.

        Returns:
            str:
                The AppWorks URL to get a list of all priorities.

        """

        return self.config()["priorityListUrl"]

    # end method definition

    def get_create_customer_url(self) -> str:
        """Return create customer URL of OTAWP.

        Returns:
            str:
                The create customer URL.

        """

        return self.config()["customerUrl"] + "?defaultinst_ct=abcd"

    # end method definition

    def get_customers_list_url(self) -> str:
        """Get OTAWP URL to retrieve a list of all customers.

        Returns:
            str:
                The AppWorks URL to get a list of all customers.

        """

        return self.config()["customerListUrl"]

    # end method definition

    def get_create_casetype_url(self) -> str:
        """Return create case type URL of OTAWP.

        Returns:
            str:
                The create case type URL.

        """

        return self.config()["caseTypeUrl"] + "?defaultinst_ct=abcd"

    # end method definition

    def get_casetypes_list_url(self) -> str:
        """Get OTAWP URL to retrieve a list of all case types.

        Returns:
            str:
                The get all case types URL.

        """

        return self.config()["caseTypeListUrl"]

    # end method definition

    def get_create_category_url(self) -> str:
        """Get OTAWP URL to create a category.

        Returns:
            str:
                The create category URL.

        """

        return self.config()["categoryUrl"] + "?defaultinst_ct=abcd"

    # end method definition

    def get_categories_list_url(self) -> str:
        """Get OTAWP URL to retrieve a list of all categories.

        Returns:
            str:
                The get all categories URL.

        """

        return self.config()["categoryListUrl"]

    # end method definition

    def get_create_case_url(self) -> str:
        """Get OTAWP URL to create a case (e.g. a loan).

        Returns:
            str:
                The create case URL.

        """

        return self.config()["caseUrl"] + "?defaultinst_ct=abcd"

    # end method definition

    def get_cases_list_url(self) -> str:
        """Return get all loans URL of OTAWP.

        Returns:
            str:
                The get all loans URL.

        """

        return self.config()["caseListUrl"]

    # end method definition

    def parse_xml(self, xml_string: str) -> dict:
        """Parse XML string and return a dictionary without namespaces.

        Args:
            xml_string (str):
                The XML string to process.

        Returns:
            dict:
                The XML structure converted to a dictionary.

        """

        return XML.xml_to_dict(xml_string=xml_string)

    # end method definition

    def find_key(self, data: dict | list, target_key: str) -> str | None:
        """Recursively search for a key in a nested dictionary and return its value.

        Args:
            data (dict | list):
                The data structure to find a key in.
            target_key (str):
                The key to find.

        Returns:
            str | None:
                The value for the key. None in case of an error.

        """

        if isinstance(data, dict):
            if target_key in data:
                return data[target_key]
            for value in data.values():
                result = self.find_key(value, target_key)
                if result is not None:
                    return result
        elif isinstance(data, list):
            for item in data:
                result = self.find_key(item, target_key)
                if result is not None:
                    return result

        return None

    # end method definition

    def get_soap_element(self, soap_response: str, soap_tag: str) -> str | None:
        """Retrieve an element from the XML SOAP response.

        Args:
            soap_response (str):
                The unparsed XML string of the SOAP response.
            soap_tag (str):
                The XML tag name (without namespace) of the element
                incuding the text to be returned.

        Returns:
            str | None:
                SOAP message if found in the SOAP response or NONE otherwise.

        """

        soap_data = self.parse_xml(soap_response)
        soap_string = self.find_key(data=soap_data, target_key=soap_tag)

        return soap_string

    # end method definition

    def do_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        cookies: dict | None = None,
        data: dict | None = None,
        json_data: dict | None = None,
        files: dict | None = None,
        timeout: float | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        show_warning: bool = False,
        warning_message: str = "",
        failure_message: str = "",
        success_message: str = "",
        parse_request_response: bool = True,
        verify: bool = True,
    ) -> dict | None:
        """Call an AppWorks REST API in a safe way.

        Args:
            url (str):
                The URL to send the request to.
            method (str, optional):
                HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional):
                Request Headers. Defaults to None.
            cookies (dict | None, optional):
                Request cookies. Defaults to None.
            data (dict | None, optional):
                Request payload. Defaults to None
            json_data (dict | None, optional):
                Request payload for the JSON parameter. Defaults to None.
            files (dict | None, optional):
                Dictionary of {"name": file-tuple} for multipart encoding upload.
                The file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            timeout (float | None, optional):
                Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed REST call.
                If False, then only a warning is logged. Defaults to True.
            show_warning (bool, optional):
                Whether or not an warning should be logged in case of a
                failed REST call.
                If False, then only a warning is logged. Defaults to True.
            warning_message (str, optional):
                Specific warning message. Defaults to "". If not given the error_message will be used.
            failure_message (str, optional):
                Specific error message. Defaults to "".
            success_message (str, optional):
                Specific success message. Defaults to "".
            parse_request_response (bool, optional):
                If True the response.text will be interpreted as json and loaded into a dictionary.
                True is the default.
            user_credentials (bool, optional):
                Defines if admin or user credentials are used for the REST API call.
                Default = False = admin credentials
            verify (bool, optional):
                Specify whether or not SSL certificates should be verified when making an HTTPS request.
                Default = True

        Returns:
            dict | None:
                Response of OTDS REST API or None in case of an error.

        """

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
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    verify=verify,
                )

            except requests.RequestException as req_exception:
                self.logger.error(
                    "%s; error -> %s",
                    failure_message if failure_message else "Request to -> %s failed",
                    str(req_exception),
                )
                return None

            if response.ok:
                if success_message:
                    self.logger.info(success_message)
                if parse_request_response:
                    return self.parse_request_response(response_object=response, show_error=show_error)
                else:
                    return response
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                self.logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
                continue
            elif show_error:
                self.logger.error(
                    "%s; status -> %s/%s; error -> %s",
                    failure_message,
                    response.status_code,
                    HTTPStatus(response.status_code).phrase,
                    response.text,
                )
            elif show_warning:
                self.logger.warning(
                    "%s; status -> %s/%s; warning -> %s",
                    warning_message if warning_message else failure_message,
                    response.status_code,
                    HTTPStatus(response.status_code).phrase,
                    response.text,
                )
            return None
        # end while True

    # end method definition

    def parse_request_response(
        self,
        response_object: object,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Convert the text property of a request response object to a Python dict in a safe way.

        Properly handle exceptions.

        AppWorks may produce corrupt response when it gets restarted
        or hitting resource limits. So we try to avoid a fatal error and bail
        out more gracefully.

        Args:
            response_object (object):
                This is reponse object delivered by the request call.
            additional_error_message (str, optional):
                Print a custom error message.
            show_error (bool, optional):
                If True log an error, if False log a warning.

        Returns:
            dict:
                Response or None in case of an error.

        """

        if not response_object:
            return None

        try:
            dict_object = json.loads(response_object.text)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSon. {}; error -> {}".format(
                    additional_error_message,
                    exception,
                )
            else:
                message = "Cannot decode response as JSon; error -> {}".format(
                    exception,
                )
            if show_error:
                self.logger.error(message)
            else:
                self.logger.warning(message)
            return None

        return dict_object

    # end method definition

    def get_entity_value(self, entity: dict, key: str, show_error: bool = True) -> str | int | None:
        """Read an entity value from the REST API response.

        Args:
            entity (dict):
                An entity - typically consisting of a dictionary with a "_links" and "Properties" keys. Example:
                {
                    '_links': {
                        'item': {...}
                    },
                    'Properties': {
                        'Name': 'Test 1',
                        'Description': 'Test 1 Description',
                        'CasePrefix': 'TEST',
                        'Status': 1
                    }
                }
            key (str):
                Key to find (e.g., "id", "name"). For key "id" there's a special
                handling as the ID is only provided in the 'href' in the '_links'
                sub-dictionary.
            show_error (bool, optional):
                Whether an error or just a warning should be logged.

        Returns:
            str | None:
                Value of the entity property with the given key, or None if no value is found.

        """

        if not entity or "Properties" not in entity:
            return None

        properties = entity["Properties"]

        if key not in properties and key != "id":
            if show_error:
                self.logger.error("Key -> '%s' not found in entity -> '%s'!", key, str(entity))
            return None

        # special handling of IDs which we extract from the self href:
        if key == "id" and "_links" in entity:
            links = entity["_links"]
            if "item" in links:
                links = links["item"]
            self_link = links.get("href")
            match = re.search(r"/(\d+)(?=[^/]*$)", self_link)
            if not match:
                return None
            return int(match.group(1))

        return properties[key]

    # end method definition

    def get_result_value(
        self,
        response: dict,
        entity_type: str,
        key: str,
        index: int = 0,
        show_error: bool = True,
    ) -> str | int | None:
        """Read an item value from the REST API response.

        Args:
            response (dict):
                REST API response object.
            entity_type (str):
                Name of the sub-dictionary holding the actual values.
                This typically stands for the type of the AppWorks entity.
            key (str):
                Key to find (e.g., "id", "name").
            index (int, optional):
                Index to use if a list of results is delivered (1st element has index 0).
                Defaults to 0.
            show_error (bool, optional):
                Whether an error or just a warning should be logged.

        Returns:
            str | int | None:
                Value of the item with the given key, or None if no value is found.

        """

        if not response:
            return None

        if "_embedded" not in response:
            return None

        embedded_data = response["_embedded"]

        if entity_type not in embedded_data:
            if show_error:
                self.logger.error("Entity type -> '%s' is not included in response!", entity_type)
            return None

        entity_list = embedded_data[entity_type]

        try:
            entity = entity_list[index]
        except KeyError:
            if show_error:
                self.logger.error("Response does not have an entity at index -> %d", index)
            return None

        return self.get_entity_value(entity=entity, key=key, show_error=show_error)

    # end method definition

    def get_result_values(
        self,
        response: dict,
        entity_type: str,
        key: str,
        show_error: bool = True,
    ) -> list | None:
        """Read an values from the REST API response.

        Args:
            response (dict):
                REST API response object.
            entity_type (str):
                Name of the sub-dictionary holding the actual values.
                This typically stands for the type of the AppWorks entity.
            key (str):
                Key to find (e.g., "id", "name").
            show_error (bool, optional):
                Whether an error or just a warning should be logged.

        Returns:
            list | None:
                Values of the items with the given key, or [] if the list
                of values is empty, or None if the response is not in the
                expected format.

        """

        results = []

        if not response:
            return None

        if "_embedded" not in response:
            return None

        embedded_data = response["_embedded"]

        if entity_type not in embedded_data:
            if show_error:
                self.logger.error("Entity type -> '%s' is not included in response!", entity_type)
            return None

        entity_list = embedded_data[entity_type]

        for entity in entity_list or []:
            entity_value = self.get_entity_value(entity=entity, key=key, show_error=show_error)
            if entity_value:
                results.append(entity_value)

        return results

    # end method definition

    def get_result_item(
        self,
        response: dict,
        entity_type: str,
        key: str,
        value: str,
        show_error: bool = True,
    ) -> dict | None:
        """Check existence of key / value pair in the response properties of an REST API call.

        Args:
            response (dict):
                REST response from an AppWorks REST Call.
                Name of the sub-dictionary holding the actual values.
                This typically stands for the type of the AppWorks entity.
            entity_type (str):
                Name of the sub-dictionary holding the actual values.
                This typically stands for the type of the AppWorks entity.
            key (str):
                The property name (key).
            value (str):
                The value to find in the item with the matching key.
            show_error (bool, optional):
                Whether an error or just a warning should be logged.

        Returns:
            dict | None:
                Entity data or None in case entity with key/value was not found.

        """

        if not response:
            return None

        if "_embedded" not in response:
            return None

        embedded_data = response["_embedded"]

        if entity_type not in embedded_data:
            if show_error:
                self.logger.error("Entity type -> '%s' is not included in response!", entity_type)
            return None

        entity_list = embedded_data[entity_type]

        for entity in entity_list:
            if "Properties" not in entity:
                continue

            properties = entity["Properties"]

            if key not in properties:
                if show_error:
                    self.logger.error("Key -> '%s' is not in properties of entity -> '%s'!", key, str(entity))
                continue
            if properties[key] == value:
                return entity

        return None

    # end method definition

    def authenticate(self, revalidate: bool = False) -> dict | None:
        """Authenticate at AppWorks.

        Args:
            revalidate (bool, optional):
                Determine if a re-authentication is enforced
                (e.g. if session has timed out with 401 error).

        Returns:
            dict | None:
                Cookie information. Also stores cookie information in self._cookie.
                None in case of an error.

        Example:
        {
            'defaultinst_SAMLart': 'e0pBVkEtQUVTL0...tj5m6w==',
            'defaultinst_ct': 'abcd'
        }

        """

        self.logger.info("Authenticate at AppWorks organization -> '%s'...", self.config()["organization"])

        if self._cookie and not revalidate:
            self.logger.debug(
                "Session still valid - return existing cookie -> %s",
                str(self._cookie),
            )
            return self._cookie

        otawp_ticket = "NotSet"

        request_url = self.credential_url()

        retries = 0
        response = None  # seems to be necessary here

        while retries < REQUEST_MAX_RETRIES:
            try:
                response = requests.post(
                    url=request_url,
                    data=self.credentials(),
                    headers=REQUEST_HEADERS_XML,
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.exceptions.RequestException as exception:
                self.logger.warning(
                    "Unable to connect to OTAWP authentication endpoint -> %s; error -> %s",
                    self.credential_url(),
                    str(exception),
                )
                self.logger.warning("OTAWP service may not be ready yet. Retry in %d seconds...", REQUEST_RETRY_DELAY)
                time.sleep(REQUEST_RETRY_DELAY)
                retries += 1
                continue

            if response.ok:
                soap_response = self.parse_xml(xml_string=response.text)
                if not soap_response:
                    self.logger.error("Failed to parse the SOAP response with the authentication data!")
                    self.logger.debug("SOAP message -> %s", response.text)
                    return None
                otawp_ticket = self.find_key(
                    data=soap_response,
                    target_key="AssertionArtifact",
                )
                if otawp_ticket:
                    self.logger.info(
                        "Successfully authenticated at AppWorks organization -> '%s' with URL -> %s and user -> '%s'.",
                        self.config()["organization"],
                        self.credential_url(),
                        self.config()["username"],
                    )
                    self.logger.debug("SAML token -> %s", otawp_ticket)
                    self._cookie = {"defaultinst_SAMLart": otawp_ticket, "defaultinst_ct": "abcd"}
                    self._otawp_ticket = otawp_ticket

                    return self._cookie
                else:
                    self.logger.error(
                        "Cannot retrieve OTAWP ticket! Received corrupt authentication data -> %s",
                        response.text,
                    )
                    return None
            else:
                self.logger.error(
                    "Failed to request an OTAWP ticket at authentication URL -> %s with user -> '%s'!%s",
                    self.credential_url(),
                    self.config()["username"],
                    " Reason -> '{}'".format(response.reason) if response.reason else "",
                )
                return None

        self.logger.error(
            "Authentication at AppWorks platform failed after %d retries. %sBailing out.",
            REQUEST_MAX_RETRIES,
            "{}. ".format(response.text) if response and response.text else "",
        )
        return None

    # end method definition

    def create_workspace(
        self, workspace_name: str, workspace_id: str, show_error: bool = True
    ) -> tuple[dict | None, bool]:
        """Create a workspace in cws.

        Args:
            workspace_name (str):
                The name of the workspace.
            workspace_id (str):
                The ID of the workspace.
            show_error (bool, optional):
                Whether to show an error or a warning instead.

        Returns:
            dict | None:
                Response dictionary or error text.
            bool:
                True, if a new workspace has been created, False if the workspace did already exist.

        """

        self.logger.info(
            "Create workspace -> '%s' (%s)...",
            workspace_name,
            workspace_id,
        )

        unique_id = uuid.uuid4()

        create_workspace_data = f"""
        <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP:Body>
                <createWorkspace xmlns="http://schemas.cordys.com/cws/runtime/types/workspace/creation/DevelopmentWorkspaceCreator/1.0" async="false" workspaceID="__CWS System__" xmlns:c="http://schemas.cordys.com/cws/1.0">
                    <instance>
                        <c:Document s="T" path="D43B04C1-CD0B-A1EB-A898-53C71DB5D652">
                            <c:Header>
                                <c:System>
                                    <c:TypeID>001A6B1E-0C0C-11DF-F5E9-866B84E5D671</c:TypeID>
                                    <c:ID>D43B04C1-CD0B-A1EB-A898-53C71DB5D652</c:ID>
                                    <c:Name>D43B04C1-CD0B-A1EB-A898-53C71DB5D652</c:Name>
                                    <c:Description>D43B04C1-CD0B-A1EB-A898-53C71DB5D652</c:Description>
                                </c:System>
                            </c:Header>
                            <c:Content>
                                <DevelopmentWorkspaceCreator type="com.cordys.cws.runtime.types.workspace.creation.DevelopmentWorkspaceCreator" runtimeDocumentID="D43B04C1-CD0B-A1EB-A898-53C71DB61652">
                                    <Workspace>
                                        <uri id="{workspace_id}"/>
                                    </Workspace>
                                </DevelopmentWorkspaceCreator>
                            </c:Content>
                        </c:Document>
                    </instance>
                    <__prefetch>
                        <Document xmlns="http://schemas.cordys.com/cws/1.0" path="{workspace_name}" s="N" isLocal="IN_LOCAL">
                            <Header>
                                <System>
                                    <ID>{workspace_id}</ID>
                                    <Name>{workspace_name}</Name>
                                    <TypeID>{{4CE11E00-2D97-45C0-BC6C-FAEC1D871026}}</TypeID>
                                    <ParentID/>
                                    <Description>{workspace_name}</Description>
                                    <CreatedBy>sysadmin</CreatedBy>
                                    <CreationDate/>
                                    <LastModifiedBy>sysadmin</LastModifiedBy>
                                    <LastModifiedDate>2021-04-21T06:52:34.254</LastModifiedDate>
                                    <FQN/>
                                    <Annotation/>
                                    <ParentID/>
                                    <OptimisticLock/>
                                </System>
                            </Header>
                            <Content>
                                <DevelopmentWorkspace xmlns="http://schemas.cordys.com/cws/runtime/types/workspace/DevelopmentWorkspace/1.0" runtimeDocumentID="D43B04C1-CD0B-A1EB-A898-53C71DB59652" type="com.cordys.cws.runtime.types.workspace.DevelopmentWorkspace">
                                    <ExternalID/>
                                    <OrganizationName/>
                                    <SCMAdapter>
                                        <uri id="{unique_id}"/>
                                    </SCMAdapter>
                                    <UpgradedTo/>
                                    <LastWorkspaceUpgradeStep/>
                                    <Metaspace/>
                                </DevelopmentWorkspace>
                            </Content>
                        </Document>
                        <Document xmlns="http://schemas.cordys.com/cws/1.0" path="{workspace_name}/Untitled No SCM adapter" s="N" isLocal="IN_LOCAL">
                            <Header>
                                <System>
                                    <ID>{unique_id}</ID>
                                    <Name>Untitled No SCM adapter</Name>
                                    <TypeID>{{E89F3F62-8CA3-4F93-95A8-F76642FD5124}}</TypeID>
                                    <ParentID>{workspace_id}</ParentID>
                                    <Description>Untitled No SCM adapter</Description>
                                    <CreatedBy>sysadmin</CreatedBy>
                                    <CreationDate/>
                                    <LastModifiedBy>sysadmin</LastModifiedBy>
                                    <LastModifiedDate>2021-04-21T06:52:34.254</LastModifiedDate>
                                    <FQN/>
                                    <Annotation/>
                                    <OptimisticLock/>
                                </System>
                            </Header>
                            <Content>
                                <NullAdapter xmlns="http://schemas.cordys.com/cws/runtime/types/teamdevelopment/NullAdapter/1.0" runtimeDocumentID="D43B04C1-CD0B-A1EB-A898-53C71DB51652" type="com.cordys.cws.runtime.types.teamdevelopment.NullAdapter">
                                    <Workspace>
                                        <uri id="{workspace_id}"/>
                                    </Workspace>
                                </NullAdapter>
                            </Content>
                        </Document>
                    </__prefetch>
                </createWorkspace>
            </SOAP:Body>
        </SOAP:Envelope>"""

        error_messages = [
            "Collaborative Workspace Service Container is not able to handle the SOAP request",
            "Service Group Lookup failure",
        ]

        exist_messages = [
            "Object already exists",
            "createWorkspaceResponse",
        ]

        request_url = self.gateway_url()

        retries = 0

        while retries < REQUEST_MAX_RETRIES:
            try:
                response = requests.post(
                    url=request_url,
                    data=create_workspace_data,
                    headers=REQUEST_HEADERS_XML,
                    cookies=self.cookie(),
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException as req_exception:
                self.logger.warning(
                    "Request to create workspace -> '%s' failed with error -> %s. Retry in %d seconds...",
                    workspace_name,
                    str(req_exception),
                    REQUEST_RETRY_DELAY,
                )
                time.sleep(REQUEST_RETRY_DELAY)
                retries += 1
                continue

            if response.ok:
                self.logger.info(
                    "Successfully created workspace -> '%s' (%s).",
                    workspace_name,
                    workspace_id,
                )
                # True indicates that a new workspaces has been created.
                return (self.parse_xml(response.text), True)

            # Check if Session has expired - then re-authenticate and try once more
            if response.status_code == 401 and retries == 0:
                self.logger.warning("Session expired. Re-authenticating...")
                self.authenticate(revalidate=True)
                retries += 1
                continue

            # Check if the workspace does exist already:
            if any(exist_message in response.text for exist_message in exist_messages):
                self.logger.info("Workspace -> '%s' with ID -> '%s' already exists!", workspace_name, workspace_id)
                self.logger.debug("SOAP message -> %s", response.text)

                # False indicates that a new workspaces has NOT been created.
                return (self.parse_xml(response.text), False)

            # Check if any error message is in the response:
            if any(error_message in response.text for error_message in error_messages):
                self.logger.warning(
                    "Workspace service error, waiting %d seconds to retry... (Retry %d of %d)",
                    REQUEST_RETRY_DELAY,
                    retries + 1,
                    REQUEST_MAX_RETRIES,
                )
                self.logger.debug("SOAP message -> %s", response.text)
                time.sleep(REQUEST_RETRY_DELAY)
                retries += 1

        # end while retries < REQUEST_MAX_RETRIES:

        # After max retries, log and return the response or handle as needed
        if show_error:
            self.logger.error(
                "Max retries reached for workspace -> '%s', unable to create workspace.",
                workspace_name,
            )
        else:
            self.logger.warning(
                "Max retries reached for workspace -> '%s', unable to create workspace.",
                workspace_name,
            )

        return (None, False)

    # end method definition

    def sync_workspace(self, workspace_name: str, workspace_id: str) -> dict | None:
        """Synchronize workspace.

        Args:
            workspace_name (str):
                The name of the workspace.
            workspace_id (str):
                The ID of the workspace.

        Returns:
            dict | None:
                Parsed response as a dictionary if successful, None otherwise.

        """

        if not workspace_id:
            self.logger.error(
                "Cannot synchronize workspace%s without a workspace ID!",
                " -> '{}'".format(workspace_name) if workspace_name else "",
            )
            return None

        self.logger.info("Starting synchronization of workspace -> '%s' (%s)...", workspace_name, workspace_id)

        # SOAP request body
        sync_workspace_data = f"""
        <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP:Body>
                <Synchronize workspaceID="{workspace_id}" xmlns="http://schemas.cordys.com/cws/synchronize/1.0">
                    <DocumentID/>
                    <Asynchronous>false</Asynchronous>
                </Synchronize>
            </SOAP:Body>
        </SOAP:Envelope>
        """

        request_url = self.gateway_url()

        self.logger.debug(
            "Synchronize workspace -> '%s' (%s); calling -> '%s'",
            workspace_name,
            workspace_id,
            request_url,
        )

        retries = 0

        while retries < REQUEST_MAX_RETRIES:
            try:
                response = requests.post(
                    url=request_url,
                    data=sync_workspace_data,
                    headers=REQUEST_HEADERS_XML,
                    cookies=self.cookie(),
                    timeout=SYNC_PUBLISH_REQUEST_TIMEOUT,
                )
            except requests.RequestException as req_exception:
                self.logger.warning(
                    "Request to synchronize workspace -> '%s' failed with error -> %s. Retry in %d seconds...",
                    workspace_name,
                    str(req_exception),
                    REQUEST_RETRY_DELAY,
                )
                time.sleep(REQUEST_RETRY_DELAY)
                retries += 1
                continue

            if response.ok:
                self.logger.info("Successfully synchronized workspace -> '%s' (%s).", workspace_name, workspace_id)
                return self.parse_xml(response.text)

            # Check if Session has expired - then re-authenticate and try once more
            if response.status_code == 401 and retries == 0:
                self.logger.warning("Session expired. Re-authenticating...")
                self.authenticate(revalidate=True)
                retries += 1
                continue

            if SOAP_FAULT_INDICATOR in response.text:
                self.logger.warning(
                    "Workspace synchronization failed with error -> '%s' when calling -> %s! Retry in %d seconds...",
                    self.get_soap_element(soap_response=response.text, soap_tag="faultstring"),
                    self.get_soap_element(soap_response=response.text, soap_tag="faultactor"),
                    REQUEST_RETRY_DELAY,
                )
                self.logger.debug("SOAP message -> %s", response.text)
            else:
                self.logger.warning(
                    "Unexpected error during workspace synchronization -> %s. Retry in %d seconds...",
                    response.text,
                    REQUEST_RETRY_DELAY,
                )
            time.sleep(REQUEST_RETRY_DELAY)
            retries += 1

        # end while retries < REQUEST_MAX_RETRIES:

        self.logger.error(
            "Synchronization failed for workspace -> '%s' after %d retries.",
            workspace_name,
            retries,
        )
        return None

    # end method definition

    def publish_project(
        self,
        workspace_name: str,
        workspace_id: str,
        project_name: str,
        project_id: str,
    ) -> bool:
        """Publish the workspace project.

        Args:
            workspace_name (str):
                The name of the workspace.
            workspace_id (str):
                The workspace ID.
            project_name (str):
                The name of the project.
            project_id (str):
                The project ID.

        Returns:
            bool:
                True if successful, False if it fails after retries.

        """

        self.logger.info(
            "Publish project -> '%s' (%s) in workspace -> '%s' (%s)...",
            project_name,
            project_id,
            workspace_name,
            workspace_id,
        )

        # Validation of parameters:
        required_fields = {
            "workspace": workspace_name,
            "workspace ID": workspace_id,
            "project": project_name,
            "project ID": project_id,
        }

        for name, value in required_fields.items():
            if not value:
                self.logger.error(
                    "Cannot publish project%s without a %s!",
                    " -> '{}'".format(project_name) if project_name else "",
                    name,
                )
                return None

        project_publish_data = f"""
        <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP:Body>
                <deployObject xmlns="http://schemas.cordys.com/cws/internal/buildhelper/BuildHelper/1.0" async="false" workspaceID="{workspace_id}" xmlns:c="http://schemas.cordys.com/cws/1.0">
                    <object>
                        <c:uri id="{project_id}"/>
                    </object>
                </deployObject>
            </SOAP:Body>
        </SOAP:Envelope>
        """

        # Initialize retry parameters
        retries = 0
        success_indicator = "deployObjectResponse"

        while retries < REQUEST_MAX_RETRIES:
            try:
                response = requests.post(
                    url=self.gateway_url(),
                    data=project_publish_data,
                    headers=REQUEST_HEADERS_XML,
                    cookies=self.cookie(),
                    timeout=SYNC_PUBLISH_REQUEST_TIMEOUT,
                )
            except requests.RequestException as req_exception:
                self.logger.warning(
                    "Request to publish project -> '%s' (%s) failed with error -> %s. Retry in %d seconds...",
                    project_name,
                    project_id,
                    str(req_exception),
                    REQUEST_RETRY_DELAY,
                )
                retries += 1
                time.sleep(REQUEST_RETRY_DELAY)
                continue

            # Check if the response is successful
            if response.ok:
                if success_indicator in response.text:
                    self.logger.info(
                        "Successfully published project -> '%s' (%s) in workspace -> '%s' (%s)",
                        project_name,
                        project_id,
                        workspace_name,
                        workspace_id,
                    )
                    return True
                else:
                    self.logger.warning(
                        "Expected success indicator -> '%s' but it was not found in response. Retrying in 30 seconds... (Attempt %d of %d)",
                        success_indicator,
                        retries + 1,
                        REQUEST_MAX_RETRIES,
                    )
            elif response.status_code == 401:
                # Check for session expiry and retry authentication
                self.logger.warning("Session has expired - re-authenticating...")
                self.authenticate(revalidate=True)
            else:
                self.logger.error(
                    "Unexpected error (status code -> %d). Retrying in 30 seconds... (Attempt %d of %d)",
                    response.status_code,
                    retries + 1,
                    REQUEST_MAX_RETRIES,
                )
                self.logger.debug(
                    "SOAP message -> %s",
                    response.text,
                )
            self.sync_workspace(workspace_name=workspace_name, workspace_id=workspace_id)
            retries += 1
            time.sleep(REQUEST_RETRY_DELAY)

        # end while retries < REQUEST_MAX_RETRIES:

        # After reaching the maximum number of retries, log failure and return False
        self.logger.error(
            "Max retries reached. Failed to publish project -> '%s' in workspace -> '%s'.",
            project_name,
            workspace_name,
        )

        return False

    # end method definition

    def create_priority(self, name: str, description: str = "", status: int = 1) -> dict | None:
        """Create Priority entity instance.

        Args:
            name (str):
                The name of the priority.
            description (str, optional):
                The description of the priority.
            status (int, optional):
                The status of the priority. Default is 1.

        Returns:
            dict:
                Request response (dictionary) or None if the REST call fails

        Example:
        {
            'Identity': {
                'Id': '327681'
            },
            '_links': {
                'self': {
                    'href': '/OpentextCaseManagement/entities/Priority/items/327681'
                }
            }
        }

        """

        # Sanity checks as the parameters come directly from payload:
        if not name:
            self.logger.error("Cannot create a priority without a name!")
            return None

        create_priority_data = {
            "Properties": {"Name": name, "Description": description, "Status": status},
        }

        request_url = self.get_create_priority_url()

        return self.do_request(
            url=request_url,
            method="POST",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            json_data=create_priority_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Request to create priority -> '{}' failed".format(name),
        )

    # end method definition

    def get_priorities(self) -> dict | None:
        """Get all priorities from entity.

        Args:
            None

        Returns:
            dict:
                Request response (dictionary with priority values) or None if the REST call fails.

        Example:
        {
            'page': {
                'skip': 0,
                'top': 0,
                'count': 4,
                'ftsEnabled': False
            },
            '_links': {
                'self': {
                    'href': '/OpentextCaseManagement/entities/Priority/lists/PriorityList'
                },
                'first': {
                    'href': '/OpentextCaseManagement/entities/Priority/lists/PriorityList'
                }
            },
            '_embedded': {
                'PriorityList': {
                    'PriorityList': [
                        {
                            '_links': {
                                'href': '/OpentextCaseManagement/entities/Priority/items/1'
                            },
                            'Properties': {
                                'Name': 'High',
                                'Description': 'High',
                                'Status': 1
                            }
                        },
                        {
                            '_links': {'item': {...}},
                            'Properties': {'Name': 'Medium', 'Description': 'Medium', 'Status': 1}
                        },
                        {
                            '_links': {'item': {...}},
                            'Properties': {'Name': 'Low', 'Description': 'Low', 'Status': 1}
                        },
                        {
                            '_links': {'item': {...}},
                            'Properties': {'Name': 'Marc Test 1', 'Description': 'Marc Test 1 Description', 'Status': 1}
                        }
                    ]
                }
            }
        }

        """

        request_url = self.get_priorities_list_url()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            timeout=REQUEST_TIMEOUT,
            failure_message="Request to get priorities failed",
        )

    # end method definition

    def get_priority_by_name(self, name: str) -> dict | None:
        """Get priority entity instance by its name.

        Args:
            name (str):
                The name of the priority.

        Returns:
            dict | None:
                Returns the priority item or None if it does not exist.

        """

        priorities = self.get_priorities()

        return self.get_result_item(response=priorities, entity_type="PriorityList", key="Name", value=name)

    # end method definition

    def get_priority_ids(self) -> list:
        """Get all priority entity instances IDs.

        Args:
            None
        Returns:
            list:
                A list with all priority IDs.

        """

        priorities = self.get_priorities()

        return self.get_result_values(response=priorities, entity_type="PriorityList", key="id") or []

    # end method definition

    def create_customer(
        self,
        customer_name: str,
        legal_business_name: str,
        trading_name: str,
    ) -> dict | None:
        """Create customer entity instance.

        Args:
            customer_name (str):
                The name of the customer.
            legal_business_name (str):
                The legal business name.
            trading_name (str):
                The trading name.

        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails.

        """

        # Sanity checks as the parameters come directly from payload:
        if not customer_name:
            self.logger.error("Cannot create a customer without a name!")
            return None

        create_customer_data = {
            "Properties": {
                "CustomerName": customer_name,
                "LegalBusinessName": legal_business_name,
                "TradingName": trading_name,
            },
        }

        request_url = self.get_create_customer_url()

        return self.do_request(
            url=request_url,
            method="POST",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            json_data=create_customer_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Request to create customer -> '{}' failed".format(customer_name),
        )

    # end method definition

    def get_customers(self) -> dict | None:
        """Get all customer entity instances.

        Args:
            None

        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails.

        Example:
        {
            'page': {
                'skip': 0,
                'top': 0,
                'count': 4,
                'ftsEnabled': False
            },
            '_links': {
                'self': {
                    'href': '/OpentextCaseManagement/entities/Customer/lists/CustomerList'
                },
                'first': {...}
            },
            '_embedded': {
                'CustomerList': [
                    {
                        '_links': {
                            'item': {
                                'href': '/OpentextCaseManagement/entities/Customer/items/1'
                            }
                        },
                        'Properties': {
                            'CustomerName': 'InaPlex Limited',
                            'LegalBusinessName': 'InaPlex Limited',
                            'TradingName': 'InaPlex Limited'
                        }
                    },
                    {
                        '_links': {...},
                        'Properties': {...}
                    },
                    ...
                ]
            }
        }

        """

        request_url = self.get_customers_list_url()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            timeout=REQUEST_TIMEOUT,
            failure_message="Request to get customers failed",
        )

    # end method definition

    def get_customer_by_name(self, name: str) -> dict | None:
        """Get customer entity instance by its name.

        Args:
            name (str):
                The name of the customer.

        Returns:
            dict | None:
                Returns the customer data or None if no customer with the given name exists.

        """

        customers = self.get_customers()

        return self.get_result_item(response=customers, entity_type="CustomerList", key="CustomerName", value=name)

    # end method definition

    def get_customer_ids(self) -> list:
        """Get all customer entity instances IDs.

        Args:
            None
        Returns:
            list:
                A list of all customer IDs.

        """

        customers = self.get_customers()

        return self.get_result_values(response=customers, entity_type="CustomerList", key="id") or []

    # end method definition

    def create_case_type(self, name: str, description: str = "", status: int = 1) -> dict | None:
        """Create case type entity instances.

        Args:
            name (str):
                The name of the case type.
            description (str, optional):
                The description of the case type.
            status (int, optional): status

        Returns:
            dict:
                Request response (dictionary) or None if the REST call fails.

        """

        # Sanity checks as the parameters come directly from payload:
        if not name:
            self.logger.error("Cannot create a case type without a name!")
            return None

        create_case_type_data = {
            "Properties": {"Name": name, "Description": description, "Status": status},
        }

        request_url = self.get_create_casetype_url()

        return self.do_request(
            url=request_url,
            method="POST",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            json_data=create_case_type_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Request to create case type -> '{}' failed".format(name),
        )

    # end method definition

    def get_case_types(self) -> dict | None:
        """Get all case type entity instances.

        Args:
            None

        Returns:
            dict:
                Request response (dictionary) or None if the REST call fails.

        Example:
        {
            'page': {
                'skip': 0,
                'top': 0,
                'count': 5,
                'ftsEnabled': False
            },
            '_links': {
                'self': {
                    'href': '/OpentextCaseManagement/entities/CaseType/lists/AllCaseTypes'
                },
                'first': {...}
            },
            '_embedded': {
                'AllCaseTypes': [
                    {
                        '_links': {
                            'item': {
                                'href': '/OpentextCaseManagement/entities/CaseType/items/1'
                            }
                        },
                        'Properties': {
                            'Name': 'Query',
                            'Description': 'Query',
                            'Status': 1
                        }
                    },
                    {
                        '_links': {...},
                        'Properties': {...}
                    },
                    ...
                ]
            }
        }

        """

        request_url = self.get_casetypes_list_url()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            timeout=REQUEST_TIMEOUT,
            failure_message="Request to get case types failed",
        )

    # end method definition

    def get_case_type_by_name(self, name: str) -> dict | None:
        """Get case type entity instance by its name.

        Args:
            name (str):
                The name of the case type.

        Returns:
            dict | None:
                Returns the case type data or None if no case type with the given name exists.

        """

        case_types = self.get_case_types()

        return self.get_result_item(response=case_types, entity_type="AllCaseTypes", key="Name", value=name)

    # end method definition

    def get_case_type_ids(self) -> list:
        """Get All CaseType entity instances IDs.

        Args:
            None

        Returns:
            list:
                List of all case type IDs.

        """

        case_types = self.get_case_types()

        return self.get_result_values(response=case_types, entity_type="AllCaseTypes", key="id") or []

    # end method definition

    def create_category(
        self,
        case_prefix: str,
        name: str,
        description: str,
        status: int = 1,
    ) -> dict | None:
        """Create category entity instance.

        Args:
            case_prefix (str):
                The prefix for the case.
            description (str):
                The description for the category.
            name (str):
                The name of the category.
            status (int):
                The status code.

        Returns:
            dict:
                Request response (dictionary) or None if the REST call fails.

        Example:
        {
            'Identity': {
                'Id': '327681'
            },
            '_links': {
                'self': {
                    href': '/OpentextCaseManagement/entities/Category/items/327681'
                }
            }
        }

        """

        # Sanity checks as the parameters come directly from payload:
        if not name:
            self.logger.error("Cannot create a category without a name!")
            return None

        create_category_data = {
            "Properties": {
                "CasePrefix": case_prefix,
                "Description": description,
                "Name": name,
                "Status": status,
            },
        }

        request_url = self.get_create_category_url()

        return self.do_request(
            url=request_url,
            method="POST",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            json_data=create_category_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to create category -> '{}'".format(name),
        )

    # end method definition

    def get_categories(self) -> dict | None:
        """Get all categories entity instances.

        Args:
            None
        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails.

        Example:
        {
            'page': {
                'skip': 0,
                'top': 0,
                'count': 3,
                'ftsEnabled': False
            },
            '_links': {
                'self': {
                    'href': '/OpentextCaseManagement/entities/Category/lists/CategoryList'
                },
                'first': {...}
            },
            '_embedded': {
                'CategoryList': [
                    {
                        '_links': {
                            'item': {
                                'href': '/OpentextCaseManagement/entities/Category/items/1'
                            }
                        },
                        'Properties': {
                            'Name': 'Short Term Loan',
                            'Description': 'Short Term Loan',
                            'CasePrefix': 'LOAN',
                            'Status': 1
                        }
                    },
                    {
                        '_links': {...},
                        'Properties': {...}
                    },
                    {
                        '_links': {...},
                        'Properties': {...}
                    }
                ]
            }
        }

        """

        request_url = self.get_categories_list_url()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get categories",
        )

    # end method definition

    def get_category_by_name(self, name: str) -> dict | None:
        """Get category entity instance by its name.

        The category ID is only provided by the 'href' in '_links' / 'item'.

        Args:
            name (str):
                The name of the category.

        Returns:
            dict | None:
                Returns the category item or None if a category with the given name does not exist.

        Example:
        {
            '_links': {
                'item': {
                    'href': '/OpentextCaseManagement/entities/Category/items/327681'
                }
            },
            'Properties': {
                'Name': 'Test 1',
                'Description': 'Test 1 Description',
                'CasePrefix': 'TEST',
                'Status': 1
            }
        }

        """

        categories = self.get_categories()

        return self.get_result_item(response=categories, entity_type="CategoryList", key="Name", value=name)

    # end method definition

    def get_category_ids(self) -> list:
        """Get All category entity instances IDs.

        Args:
            None
        Returns:
            list: list of category IDs

        """

        categories = self.get_categories()

        return self.get_result_values(response=categories, entity_type="CategoryList", key="id") or []

    # end method definition

    def create_sub_category(
        self,
        parent_id: int,
        name: str,
        description: str = "",
        status: int = 1,
    ) -> dict | None:
        """Create sub categoy entity instances.

        Args:
            parent_id (int):
                The parent ID of the category.
            name (str):
                The name of the sub-category.
            description (str, optional):
                The description for the sub-category.
            status (int, optional):
                The status ID. Default is 1.

        Returns:
            dict:
                Request response (dictionary) or None if the REST call fails.

        """

        # Sanity checks as the parameters come directly from payload:
        if not name:
            self.logger.error("Cannot create a sub-category without a name!")
            return None
        if not parent_id:
            self.logger.error("Cannot create a sub-category -> '%s' without a parent category ID!", name)
            return None

        create_sub_category_data = {
            "Properties": {"Name": name, "Description": description, "Status": status},
        }

        request_url = (
            self.config()["categoryUrl"] + "/items/" + str(parent_id) + "/childEntities/SubCategory?defaultinst_ct=abcd"
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            json_data=create_sub_category_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to create sub-category -> '{}' with parent category ID -> {}".format(
                name, parent_id
            ),
        )

    # end method definition

    def get_sub_categories(self, parent_id: int) -> dict | None:
        """Get all sub categeries entity instances.

        Args:
            parent_id (int):
                The parent ID of the sub categories.

        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails.

        Example:
        {
            'page': {
                'skip': 0,
                'top': 10,
                'count': 1
            },
            '_links': {
                'self': {...},
                'first': {...}
            },
            '_embedded': {
                'SubCategory': [
                    {
                        '_links': {...},
                        'Identity': {'Id': '1'},
                        'Properties': {'Name': 'Business', 'Description': 'Business', 'Status': 1},
                        'ParentCategory': {
                            '_links': {
                                'self': {'href': '/OpentextCaseManagement/entities/Category/items/1/childEntities/SubCategory/items/1'}
                            },
                            'Properties': {
                                'CasePrefix': 'LOAN',
                                'Description': 'Short Term Loan',
                                'Name': 'Short Term Loan',
                                'Status': 1
                            }
                        }
                    }
                ]
            }
        }

        """

        request_url = self.config()["categoryUrl"] + "/items/" + str(parent_id) + "/childEntities/SubCategory"

        return self.do_request(
            url=request_url,
            method="GET",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get sub-categories for parent category with ID -> {}".format(parent_id),
        )

    # end method definition

    def get_sub_category_by_parent_and_name(self, parent_id: int, name: str) -> dict | None:
        """Get sub category entity instance by its name.

        Args:
            parent_id (int):
                The ID of the parent category.
            name (str):
                The name of the sub category.

        Returns:
            dict | None:
                Returns the sub-category item or None if the sub-category with this name
                does not exist in the parent category with the given ID.

        """

        # Get all sub-categories under a given category provided by the parent ID:
        sub_categories = self.get_sub_categories(parent_id=parent_id)

        return self.get_result_item(response=sub_categories, entity_type="SubCategory", key="Name", value=name)

    # end method definition

    def get_sub_category_id(self, parent_id: int, name: str) -> int | None:
        """Get the sub category entity instance ID.

        Args:
            parent_id (int):
                ID of the parent category.
            name (str):
                The name of the sub-category.

        Returns:
            int | None:
                Returns the sub-category ID if it exists with the given name in a given parent category.
                Else returns None.

        """

        sub_cat = self.get_sub_category_by_parent_and_name(parent_id=parent_id, name=name)
        if not sub_cat or "Identity" not in sub_cat:
            return None

        return sub_cat["Identity"].get("Id")

    # end method definition

    def create_case(
        self,
        subject: str,
        description: str,
        loan_amount: str,
        loan_duration_in_months: str,
        category_id: str,
        sub_category_id: str,
        priority_id: str,
        case_type_id: str,
        customer_id: str,
    ) -> dict | None:
        """Create a case entity instance.

        The category, priority, case type and customer entities are
        referred to with their IDs. These entities need to be created
        beforehand.

        TODO: This is currently hard-coded for loan cases. Need to be more generic.

        Args:
            subject (str):
                The subject of the case.
            description (str):
                The description of the case.
            loan_amount (str):
                The loan amount of the case.
            loan_duration_in_months (str):
                The loan duration of the case (in number of months).
            category_id (str):
                The category ID of the case.
            sub_category_id (str):
                The sub-category ID of the case.
            priority_id (str):
                The priority ID of the case.
            case_type_id (str):
                The case type (service) ID of the case.
            customer_id (str):
                The ID of the customer for the case.

        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails

        """

        # Validation of parameters:
        required_fields = {
            "subject": subject,
            "category ID": category_id,
            "sub-category ID": sub_category_id,
            "priority ID": priority_id,
            "case type ID": case_type_id,
            "customer ID": customer_id,
        }

        for name, value in required_fields.items():
            if not value:
                self.logger.error("Cannot create a case without a %s!", name)
                return None

        create_case_data = f"""
        <SOAP:Envelope xmlns:SOAP=\"http://schemas.xmlsoap.org/soap/envelope/\">
            <SOAP:Body>
                <CreateCase xmlns=\"http://schemas/OpentextCaseManagement/Case/operations\">
                    <ns0:Case-create xmlns:ns0=\"http://schemas/OpentextCaseManagement/Case\">
                        <ns0:Subject>{subject}</ns0:Subject>
                        <ns0:Description>{description}</ns0:Description>
                        <ns0:LoanAmount>{loan_amount}</ns0:LoanAmount>
                        <ns0:LoanDurationInMonths>{loan_duration_in_months}</ns0:LoanDurationInMonths>
                        <ns0:CaseType>
                            <ns1:CaseType-id xmlns:ns1=\"http://schemas/OpentextCaseManagement/CaseType\">
                                <ns1:Id>{case_type_id}</ns1:Id>
                            </ns1:CaseType-id>
                        </ns0:CaseType>
                        <ns0:Category>
                            <ns2:Category-id xmlns:ns2=\"http://schemas/OpentextCaseManagement/Category\">
                                <ns2:Id>{category_id}</ns2:Id>
                            </ns2:Category-id>
                        </ns0:Category>
                        <ns0:SubCategory>
                            <ns5:SubCategory-id xmlns:ns5=\"http://schemas/OpentextCaseManagement/Category.SubCategory\">
                                <ns5:Id>{category_id}</ns5:Id>
                                <ns5:Id1>{sub_category_id}</ns5:Id1>
                            </ns5:SubCategory-id>
                        </ns0:SubCategory>
                        <ns0:Priority>
                            <ns3:Priority-id xmlns:ns3=\"http://schemas/OpentextCaseManagement/Priority\">
                                <ns3:Id>{priority_id}</ns3:Id>
                            </ns3:Priority-id>
                        </ns0:Priority>
                        <ns0:ToCustomer>
                            <ns9:Customer-id xmlns:ns9=\"http://schemas/OpentextCaseManagement/Customer\">
                                <ns9:Id>{customer_id}</ns9:Id>
                            </ns9:Customer-id>
                        </ns0:ToCustomer>
                    </ns0:Case-create>
                </CreateCase>
            </SOAP:Body>
        </SOAP:Envelope>
        """

        request_url = self.gateway_url()

        self.logger.debug(
            "Create case with subject -> '%s'; calling -> '%s'",
            subject,
            request_url,
        )

        retries = 0
        while True:
            try:
                response = requests.post(
                    url=request_url,
                    data=create_case_data,
                    headers=REQUEST_HEADERS_XML,
                    cookies=self.cookie(),
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException as req_exception:
                self.logger.error(
                    "Request to create case with subject -> '%s' failed with error -> %s",
                    subject,
                    str(req_exception),
                )
                return None

            if response.ok:
                return self.parse_xml(response.text)
            elif response.status_code == 401 and retries == 0:
                self.logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            else:
                self.logger.error(
                    "Failed to create case with subject -> '%s' for customer with ID -> '%s' with error -> '%s' when calling -> %s!",
                    subject,
                    customer_id,
                    self.get_soap_element(soap_response=response.text, soap_tag="faultstring"),
                    self.get_soap_element(soap_response=response.text, soap_tag="faultactor"),
                )
                self.logger.debug("SOAP message -> %s", response.text)
                return None

    # end method definition

    def get_cases(self) -> dict | None:
        """Get all case entity instances.

        Args:
           None

        Returns:
            dict:
                Request response (dictionary) or None if the REST call fails.

        """

        request_url = self.get_cases_list_url()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=REQUEST_HEADERS_JSON,
            cookies=self.cookie(),
            timeout=REQUEST_TIMEOUT,
            failure_message="Request to get cases failed",
        )

    # end method definition

    def get_case_by_name(self, name: str) -> dict | None:
        """Get case instance by its name.

        Args:
            name (str):
                The name of the case.

        Returns:
            dict | None:
                Returns the category item or None if a category with the given name does not exist.

        """

        categories = self.get_cases()

        return self.get_result_item(response=categories, entity_type="AllCasesList", key="Name", value=name)

    # end method definition

    def create_users_from_config_file(self, otawpsection: str, otds_object: OTDS) -> None:
        """Read user information from customizer file and call create user method.

        Args:
            otawpsection (str):
                Payload section for AppWorks.
            otds_object (OTDS):
                The OTDS object.

        Returns:
            None

        """

        otds = otawpsection.get("otds", {})
        if otds is not None:
            users = otds.get("users", [])
            if users is not None:
                for user in users:
                    otds_object.add_user(
                        user.get("partition"),
                        user.get("name"),
                        user.get("description"),
                        user.get("first_name"),
                        user.get("last_name"),
                        user.get("email"),
                    )
                    roles = otds.get("roles", [])
                    if roles is not None:
                        for role in roles:
                            otds_object.add_user_to_group(
                                user.get("name") + "@" + user.get("partition"),
                                role.get("name"),
                            )
                    else:
                        self.logger.warning(
                            "Roles section not in payload for AppWorks users.",
                        )
            else:
                self.logger.error(
                    "User section not in payload for AppWorks users.",
                )
        else:
            self.logger.error(
                "OTDS section not in payload for AppWorks users.",
            )

    # end method definition

    def create_roles_from_config_file(self, otawpsection: str, otds_object: OTDS) -> None:
        """Read grop information from customizer file and call create grop method.

        Args:
            otawpsection (str):
                Payload section for AppWorks.
            otds_object (OTDS):
                The OTDS object used to access the OTDS REST API.

        Returns:
            None

        """

        otds = otawpsection.get("otds", {})
        if otds is not None:
            roles = otds.get("roles", [])
            if roles is not None:
                for role in roles:
                    # Add new group if it does not yet exist:
                    if not otds_object.get_group(group=role.get("name"), show_error=False):
                        otds_object.add_group(
                            role.get("partition"),
                            role.get("name"),
                            role.get("description"),
                        )
            else:
                self.logger.error(
                    "Roles section not in payload for AppWorks roles/groups.",
                )
        else:
            self.logger.error(
                "OTDS section not in payload for AppWorks roles/groups.",
            )

    # end method definition

    def create_cws_config(
        self,
        partition: str,
        resource_name: str,
        otcs_url: str,
    ) -> dict | None:
        """Create a workspace configuration in CWS.

        Args:
            partition (str):
                The partition name for the workspace.
            resource_name (str):
                The resource name.
            otcs_url (str):
                The OTCS endpoint URL.

        Returns:
            dict | None:
                Response dictionary if successful, or None if the request fails.

        """

        # Construct the SOAP request body
        cws_config_data = f"""
        <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP:Header>
                <header xmlns="http://schemas.cordys.com/General/1.0/">
                    <Logger/>
                </header>
                <i18n:international xmlns:i18n="http://www.w3.org/2005/09/ws-i18n">
                    <i18n:locale>en-US</i18n:locale>
                </i18n:international>
            </SOAP:Header>
            <SOAP:Body>
                <UpdateXMLObject xmlns="http://schemas.cordys.com/1.0/xmlstore">
                    <tuple lastModified="{int(time.time() * 1000)}"
                           key="/com/ot-ps/csws/otcs_ws_config.xml"
                           level="organization"
                           name="otcs_ws_config.xml"
                           original="/com/ot-ps/csws/otcs_ws_config.xml"
                           version="organization">
                        <new>
                            <CSWSConfig>
                                <Partition>{partition}</Partition>
                                <EndPointUrl>{otcs_url}/cws/services/Authentication</EndPointUrl>
                                <Resources>
                                    <Resource type="Cordys">
                                        <Name>__OTDS#Shared#Platform#Resource__</Name>
                                        <Space>shared</Space>
                                    </Resource>
                                    <Resource type="OTCS">
                                        <Name>{resource_name}</Name>
                                        <Space>shared</Space>
                                    </Resource>
                                </Resources>
                            </CSWSConfig>
                        </new>
                    </tuple>
                </UpdateXMLObject>
            </SOAP:Body>
        </SOAP:Envelope>
        """

        error_messages = [
            "Collaborative Workspace Service Container is not able to handle the SOAP request",
            "Service Group Lookup failure",
        ]

        request_url = self.gateway_url()

        self.logger.debug(
            "Create CWS configuration with partition -> '%s', user -> '%s', and OTCS URL -> '%s'; calling -> '%s'",
            partition,
            resource_name,
            otcs_url,
            request_url,
        )

        retries = 0

        while retries < REQUEST_MAX_RETRIES:
            try:
                response = requests.post(
                    url=request_url,
                    data=cws_config_data,
                    headers=REQUEST_HEADERS_XML,
                    cookies=self.cookie(),
                    timeout=None,
                )

            except requests.RequestException as req_exception:
                self.logger.error(
                    "Request to create CWS config for partition -> '%s' failed with error -> %s. Retry in %d seconds...",
                    partition,
                    str(req_exception),
                    REQUEST_RETRY_DELAY,
                )
                retries += 1
                time.sleep(REQUEST_RETRY_DELAY)
                self.logger.info("Retrying... Attempt %d/%d", retries, REQUEST_MAX_RETRIES)
                continue

            # Handle successful response
            if response.ok:
                if any(error_message in response.text for error_message in error_messages):
                    self.logger.warning(
                        "Service error detected, retrying in %d seconds... (Retry %d of %d)",
                        REQUEST_RETRY_DELAY,
                        retries + 1,
                        REQUEST_MAX_RETRIES,
                    )
                    time.sleep(REQUEST_RETRY_DELAY)
                    retries += 1
                else:
                    self.logger.info("Successfully created CWS configuration.")
                    return self.parse_xml(response.text)

            # Handle session expiration
            if response.status_code == 401 and retries == 0:
                self.logger.warning("Session expired. Re-authenticating...")
                self.authenticate(revalidate=True)
                retries += 1
                continue

            # Handle case where object has been changed by another user:
            if "Object has been changed by other user" in response.text:
                self.logger.info("CWS config already exists")
                self.logger.debug("SOAP message -> %s", response.text)
                return self.parse_xml(response.text)

            # Log errors for failed requests
            self.logger.error("Failed to create CWS config; error -> %s", response.text)
            time.sleep(REQUEST_RETRY_DELAY)
            retries += 1
        # end while retries < REQUEST_MAX_RETRIES:

        # Log when retries are exhausted
        self.logger.error("Retry limit exceeded. CWS config creation failed.")
        return None

    # end method definition

    def verify_user_having_role(self, organization: str, user_name: str, role_name: str) -> bool:
        """Verify that the user has the specified role.

        Args:
            organization (str):
                The organization name.
            user_name (str):
                The username to verify.
            role_name (str):
                The role to check for the user.

        Returns:
            bool:
                True if the user has the role, False if not, or None if request fails.

        """

        self.logger.info(
            "Verify user -> '%s' has role -> '%s' in organization -> '%s'...", user_name, role_name, organization
        )

        # Construct the SOAP request body
        user_role_data = f"""
        <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP:Header xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
                <header xmlns="http://schemas.cordys.com/General/1.0/">
                    <Logger xmlns="http://schemas.cordys.com/General/1.0/"/>
                </header>
                <i18n:international xmlns:i18n="http://www.w3.org/2005/09/ws-i18n">
                    <i18n:locale>en-US</i18n:locale>
                </i18n:international>
            </SOAP:Header>
            <SOAP:Body>
                <SearchLDAP xmlns:xfr="http://schemas.cordys.com/1.0/xforms/runtime" xmlns="http://schemas.cordys.com/1.0/ldap">
                    <dn xmlns="http://schemas.cordys.com/1.0/ldap">cn=organizational users,o={organization},cn=cordys,cn=defaultInst,o=opentext.net</dn>
                    <scope xmlns="http://schemas.cordys.com/1.0/ldap">1</scope>
                    <filter xmlns="http://schemas.cordys.com/1.0/ldap">&amp;(objectclass=busorganizationaluser)(&amp;(!(cn=SYSTEM))(!(cn=anonymous))(!(cn=wcpLicUser)))(|(description=*{user_name}*)(&amp;(!(description=*))(cn=*{user_name}*)))</filter>
                    <sort xmlns="http://schemas.cordys.com/1.0/ldap">ascending</sort>
                    <sortBy xmlns="http://schemas.cordys.com/1.0/ldap"/>
                    <returnValues xmlns="http://schemas.cordys.com/1.0/ldap">false</returnValues>
                    <return xmlns="http://schemas.cordys.com/1.0/ldap"/>
                </SearchLDAP>
            </SOAP:Body>
        </SOAP:Envelope>
        """

        retries = 0

        while retries < REQUEST_MAX_RETRIES:
            try:
                response = requests.post(
                    url=self.gateway_url(),
                    data=user_role_data,
                    headers=REQUEST_HEADERS_XML,
                    cookies=self.cookie(),
                    timeout=None,
                )

            except requests.RequestException:
                self.logger.error(
                    "Request failed during verification of user -> '%s' for role -> '%s'. Retry in %d seconds...",
                    user_name,
                    role_name,
                    REQUEST_RETRY_DELAY,
                )
                retries += 1
                time.sleep(REQUEST_RETRY_DELAY)
                self.logger.info("Retrying... Attempt %d/%d", retries, REQUEST_MAX_RETRIES)
                continue

            # Handle successful response
            if response.ok:
                if role_name in response.text:  # Corrected syntax for checking if 'Developer' is in the response text
                    self.logger.info("Verified user -> '%s' already has the role -> '%s'.", user_name, role_name)
                    return True  # Assuming the user has the role if the response contains 'Developer'
                else:
                    self.logger.info("Verified user -> '%s' does not yet have role -> '%s'.", user_name, role_name)
                    return False

            # Handle session expiration
            if response.status_code == 401 and retries == 0:
                self.logger.warning("Session expired. Re-authenticating...")
                self.authenticate(revalidate=True)
                retries += 1
                continue

            # Log errors for failed requests
            self.logger.error(
                "Failed to verify that user -> '%s' has role -> '%s'; error -> %s",
                user_name,
                role_name,
                response.text,
            )
            time.sleep(REQUEST_RETRY_DELAY)
            retries += 1
            self.logger.info("Retrying... Attempt %d/%d", retries, REQUEST_MAX_RETRIES)

        # Log when retries are exhausted
        self.logger.error("Retry limit exceeded. User role verification failed.")

        return False  # Return False if the retries limit is exceeded

    # end method definition

    def assign_role_to_user(self, organization: str, user_name: str, role_name: str) -> bool:
        """Assign a role to a user and verify the role assignment.

        Args:
            organization (str):
                The organization name.
            user_name (str):
                The username to get the role.
            role_name (str):
                The role to be assigned.

        Returns:
            bool:
                True if the user received the role, False otherwise.

        """
        self.logger.info(
            "Assign role -> '%s' to user -> '%s' in organization -> '%s'...", role_name, user_name, organization
        )

        # Check if user already has the role before making the request
        if self.verify_user_having_role(organization, user_name, role_name):
            return True

        # Construct the SOAP request body
        developer_role_data = f"""\
        <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP:Header xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
                <header xmlns="http://schemas.cordys.com/General/1.0/">
                    <Logger xmlns="http://schemas.cordys.com/General/1.0/"/>
                </header>
                <i18n:international xmlns:i18n="http://www.w3.org/2005/09/ws-i18n">
                    <i18n:locale>en-US</i18n:locale>
                </i18n:international>
            </SOAP:Header>
            <SOAP:Body>
                <Update xmlns="http://schemas.cordys.com/1.0/ldap">
                    <tuple>
                        <old>
                            <entry dn="cn=sysadmin,cn=organizational users,o={organization},cn=cordys,cn=defaultInst,o=opentext.net">
                                <role>
                                    <string>cn=everyoneIn{organization},cn=organizational roles,o={organization},cn=cordys,cn=defaultInst,o=opentext.net</string>
                                    <string>cn=Administrator,cn=Cordys@Work,cn=cordys,cn=defaultInst,o=opentext.net</string>
                                    <string>cn=OTDS Push Service,cn=OpenText OTDS Platform Push Connector,cn=cordys,cn=defaultInst,o=opentext.net</string>
                                </role>
                                <description>
                                    <string>{user_name}</string>
                                </description>
                                <cn>
                                    <string>{user_name}</string>
                                </cn>
                                <objectclass>
                                    <string>top</string>
                                    <string>busorganizationalobject</string>
                                    <string>busorganizationaluser</string>
                                </objectclass>
                                <authenticationuser>
                                    <string>cn={user_name},cn=authenticated users,cn=cordys,cn=defaultInst,o=opentext.net</string>
                                </authenticationuser>
                            </entry>
                        </old>
                        <new>
                            <entry dn="cn={user_name},cn=organizational users,o={organization},cn=cordys,cn=defaultInst,o=opentext.net">
                                <role>
                                    <string>cn=everyoneIn{organization},cn=organizational roles,o={organization},cn=cordys,cn=defaultInst,o=opentext.net</string>
                                    <string>cn=Administrator,cn=Cordys@Work,cn=cordys,cn=defaultInst,o=opentext.net</string>
                                    <string>cn=OTDS Push Service,cn=OpenText OTDS Platform Push Connector,cn=cordys,cn=defaultInst,o=opentext.net</string>
                                    <string>cn={role_name},cn=Cordys@Work,cn=cordys,cn=defaultInst,o=opentext.net</string>
                                </role>
                                <description>
                                    <string>{user_name}</string>
                                </description>
                                <cn>
                                    <string>{user_name}</string>
                                </cn>
                                <objectclass>
                                    <string>top</string>
                                    <string>busorganizationalobject</string>
                                    <string>busorganizationaluser</string>
                                </objectclass>
                                <authenticationuser>
                                    <string>cn={user_name},cn=authenticated users,cn=cordys,cn=defaultInst,o=opentext.net</string>
                                </authenticationuser>
                            </entry>
                        </new>
                    </tuple>
                </Update>
            </SOAP:Body>
        </SOAP:Envelope>
        """

        request_url = self.gateway_url()

        self.logger.debug(
            "Assign role -> '%s' to user -> '%s' in organization -> '%s'; calling -> '%s'",
            role_name,
            user_name,
            organization,
            request_url,
        )

        retries = 0

        while retries < REQUEST_MAX_RETRIES:
            try:
                response = requests.post(
                    url=request_url,
                    data=developer_role_data,
                    headers=REQUEST_HEADERS_XML,
                    cookies=self.cookie(),
                    timeout=REQUEST_TIMEOUT,
                )

                if response.ok and role_name in response.text:
                    self.logger.info("Successfully assigned the role -> '%s' to user -> '%s'.", role_name, user_name)
                    return True

                # Handle session expiration
                if response.status_code == 401 and retries == 0:
                    self.logger.warning("Session expired. Re-authenticating...")
                    self.authenticate(revalidate=True)
                    retries += 1
                    continue  # Retry immediately after re-authentication

                # Log failure response
                self.logger.error(
                    "Failed to assign role -> '%s' to user -> '%s'; error -> %s (%s)",
                    role_name,
                    user_name,
                    response.status_code,
                    response.text,
                )

            except requests.RequestException as req_exception:
                self.logger.error("Request failed; error -> %s", str(req_exception))

            retries += 1
            self.logger.info("Retrying... Attempt %d/%d", retries, REQUEST_MAX_RETRIES)
            time.sleep(REQUEST_RETRY_DELAY)

        self.logger.error("Retry limit exceeded. Role assignment failed for user '%s'.", user_name)
        return False

        # end method definition

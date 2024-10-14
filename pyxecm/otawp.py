"""
Otawp module for synchorinizing the pojects , publsh and create run time instances for that.
loanmanagement is such application.
"""

import logging
import xml.etree.ElementTree as ET
import uuid
import json
import re
import time
import requests
from .otds import OTDS

logger = logging.getLogger("pyxecm.otawp")

REQUEST_HEADERS = {
    "Content-Type": "text/xml; charset=utf-8",
    "accept": "application/xml"
}

REQUEST_FORM_HEADERS = {
    "accept": "application/xml;charset=utf-8",
    "Content-Type": "application/x-www-form-urlencoded",
}

REQUEST_HEADERS_JSON = {
    "Content-Type": "application/json; charset=utf-8",
    "accept": "application/json"
}
REQUEST_TIMEOUT = 60

class OTAWP:
    """Used to automate settings in OpenText AppWorks Platform (OTAWP)."""
    _config: dict
    _config = None
    _cookie = None
    _otawp_ticket = None

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        otawp_ticket: str | None = None,
    ):
        otawp_config = {}

        otawp_config["hostname"] = hostname if hostname else "appworks"
        otawp_config["protocol"] = protocol if protocol else "http"
        otawp_config["port"] = port if port else 8080
        otawp_config["username"] = username if username else "sysadmin"
        otawp_config["password"] = password if password else ""

        if otawp_ticket:
            self._cookie = {"defaultinst_SAMLart": otawp_ticket}

        otds_base_url = "{}://{}".format(protocol, otawp_config["hostname"])
        if str(port) not in ["80", "443"]:
            otds_base_url += f":{port}"
        otds_base_url += "/home/system"

        otawp_config["gatewayAuthenticationUrl"] = (
            otds_base_url
            + "/com.eibus.web.soap.Gateway.wcp?organization=o=system,cn=cordys,cn=defaultInst,o=opentext.net"
        )

        otawp_config["soapGatewayUrl"] = (
            otds_base_url
            + "/com.eibus.web.soap.Gateway.wcp?organization=o=system,cn=cordys,cn=defaultInst,o=opentext.net&defaultinst_ct=abcd"
        )

        otawp_config["createPriority"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Priority?defaultinst_ct=abcd"
        )
        otawp_config["getAllPriorities"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Priority/lists/PriorityList"
        )

        otawp_config["createCustomer"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Customer?defaultinst_ct=abcd"
        )
        otawp_config["getAllCustomeres"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Customer/lists/CustomerList"
        )

        otawp_config["createCaseType"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/CaseType?defaultinst_ct=abcd"
        )
        otawp_config["getAllCaseTypes"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/CaseType/lists/AllCaseTypes"
        )

        otawp_config["createCategory"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Category?defaultinst_ct=abcd"
        )
        otawp_config["getAllCategories"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Category/lists/CategoryList"
        )

        otawp_config["createSource"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Source"
        )

        otawp_config["getAllSources"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Source/lists/AllSources"
        )

        otawp_config["getAllSubCategories"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Category/childEntities/SubCategory/lists/AllSubcategories"
        )

        otawp_config["baseurl"] = (
            otds_base_url
            + ""
        )
        otawp_config["createLoan"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Case?defaultinst_ct=abcd"
        )
        otawp_config["getAllLoans"] = (
            otds_base_url
            + "/app/entityRestService/api/OpentextCaseManagement/entities/Case/lists/AllCasesList"
        )
        self._config = otawp_config

    # end method definition

    def baseurl(self) -> dict:
        """Returns the configuration dictionary
        Returns:
            dict: Configuration dictionary
        """
        return self.config()["baseurl"]

    # end method definition

    def config(self) -> dict:
        """Returns the configuration dictionary
        Returns:
            dict: Configuration dictionary
        """
        return self._config

    # end method definition

    def cookie(self) -> dict:
        """Returns the login cookie of OTAWP.
           This is set by the authenticate() method
        Returns:
            dict: OTAWP cookie
        """
        return self._cookie

    # end method definition

    def credentials(self) -> str:
        """Returns the SOAP payload with credentials (username and password)
        Returns:
            str: SOAP payload with username and password
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
        """Returns the Credentials URL of OTAWP

        Returns:
            str: Credentials URL
        """
        return self.config()["gatewayAuthenticationUrl"]

    # end method definition

    def gateway_url(self) -> str:
        """Returns soapGatewayUrl URL of OTAWP

        Returns:
            str: soapGatewayUrl URL
        """
        return self.config()["soapGatewayUrl"]

    # end method definition

    def create_priority_url(self) -> str:
        """Returns createPriority URL of OTAWP

        Returns:
            str: createPriority  URL
        """
        return self.config()["createPriority"]

    # end method definition

    def get_all_priorities_url(self) -> str:
        """Returns getAllPriorities URL of OTAWP

        Returns:
            str: getAllPriorities URL
        """
        return self.config()["getAllPriorities"]

    # end method definition

    def create_customer_url(self) -> str:
        """Returns createCustomer URL of OTAWP

        Returns:
            str:  createCustomer url
        """
        return self.config()["createCustomer"]

    # end method definition

    def get_all_customeres_url(self) -> str:
        """Returns getAllCustomeres url of OTAWP

        Returns:
            str: getAllCustomeres url
        """
        return self.config()["getAllCustomeres"]

    # end method definition

    def create_casetype_url(self) -> str:
        """Returns createCaseType url of OTAWP

        Returns:
            str: createCaseType url
        """
        return self.config()["createCaseType"]

    # end method definition

    def get_all_case_types_url(self) -> str:
        """Returns getAllCaseTypes  URL of OTAWP

        Returns:
            str: getAllCaseTypes URL
        """
        return self.config()["getAllCaseTypes"]

    # end method definition

    def create_category_url(self) -> str:
        """Returns createCategory URL of OTAWP

        Returns:
            str: createCategory URL
        """
        return self.config()["createCategory"]

    # end method definition

    def get_all_categories_url(self) -> str:
        """Returns the getAllCategories URL of OTAWP

        Returns:
            str: getAllCategories URL
        """
        return self.config()["getAllCategories"]

    # end method definition

    def get_all_loans_url(self) -> str:
        """Returns getAllLoans  URL of OTAWP

        Returns:
            str: getAllLoans URL
        """
        return self.config()["getAllLoans"]

    # end method definition

    def remove_namespace(self, tag):
        """Remove namespace from XML tag."""
        return tag.split('}', 1)[-1]

    # end method definition

    def parse_xml(self, xml_string):
        """Parse XML string and return a dictionary without namespaces."""
        def element_to_dict(element):
            """Convert XML element to dictionary."""
            tag = self.remove_namespace(element.tag)
            children = list(element)
            if children:
                return {tag: {self.remove_namespace(child.tag): element_to_dict(child) for child in children}}
            return {tag: element.text.strip() if element.text else None}
        root = ET.fromstring(xml_string)
        return element_to_dict(root)

    # end method definition

    def find_key(self, data, target_key):
        """Recursively search for a key in a nested dictionary and return its value."""
        if isinstance(data, dict):
            if target_key in data:
                return data[target_key]
            for _, value in data.items():
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

    def parse_request_response(
        self,
        response_object: object,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Converts the text property of a request response object to a Python dict in a safe way
            that also handles exceptions.

            Content Server may produce corrupt response when it gets restarted
            or hitting resource limits. So we try to avoid a fatal error and bail
            out more gracefully.

        Args:
            response_object (object): this is reponse object delivered by the request call
            additional_error_message (str): print a custom error message
            show_error (bool): if True log an error, if False log a warning

        Returns:
            dict: response or None in case of an error
        """

        if not response_object:
            return None

        try:
            dict_object = json.loads(response_object.text)
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
        return dict_object

    # end method definition

    def authenticate(self, revalidate: bool = False) -> dict | None:
        """Authenticate at appworks.

        Args:
            revalidate (bool, optional): determine if a re-authentication is enforced
                                         (e.g. if session has timed out with 401 error)
        Returns:
            dict: Cookie information. Also stores cookie information in self._cookie
        """

        logger.info("SAMLart generation started")
        if self._cookie and not revalidate:
            logger.info(
                "Session still valid - return existing cookie -> %s",
                str(self._cookie),
            )
            return self._cookie

        otawp_ticket = "NotSet"

        response = None
        try:
            self.credentials()
            response = requests.post(
                url=self.credential_url(),
                data=self.credentials(),
                headers=REQUEST_HEADERS,
                timeout=REQUEST_TIMEOUT
            )
        except requests.exceptions.RequestException as exception:
            logger.warning(
                "Unable to connect to -> %s; error -> %s",
                self.credential_url(),
                exception.strerror,
            )
            logger.warning("OTAWP service may not be ready yet.")
            return None

        if response.ok:
            logger.info("SAMLart generated successfully")
            authenticate_dict = self.parse_xml(response.text)
            if not authenticate_dict:
                return None
            assertion_artifact_dict = self.find_key(
                authenticate_dict, "AssertionArtifact"
            )
            if isinstance(assertion_artifact_dict, dict):
                otawp_ticket = assertion_artifact_dict.get("AssertionArtifact")
                logger.info("SAML token -> %s", otawp_ticket)
        else:
            logger.error("Failed to request an OTAWP ticket; error -> %s", response.text)
            return None

        self._cookie = {"defaultinst_SAMLart": otawp_ticket, "defaultinst_ct": "abcd"}
        self._otawp_ticket = otawp_ticket

        return self._cookie

    # end method definition

    def create_workspace(
        self,
        workspace_name: str,
        workspace_id: str
    ) -> dict | None:
        """Creates a workspace in cws
        Args:
            workspace_name (str): workspace_name
            workspace_id (str): workspace_id
        Returns:
            response test or error text
        """

        logger.info(
            "Create workspace with name -> '%s' and ID -> %s...",
            workspace_name,
            workspace_id,
        )
        unique_id = uuid.uuid4()

        license_post_body_json = f"""<SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
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

        retries = 0
        while True:
            response = requests.post(
                url=self.gateway_url(),
                data=license_post_body_json,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info(
                    "Successfully created workspace -> '%s' with ID -> %s",
                    workspace_name,
                    workspace_id,
                )
                return response.text
            # Check if Session has expired - then re-authenticate and try once more
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return response.text

    # end method definition

    def sync_workspace(
        self,
        workspace_name: str,
        workspace_id: str
    ) -> dict | None:
        """ sync workspaces
        Args:
            workspace_name (str): workspace_name
            workspace_id (str): workspace_id
        Returns:
             Request response (dictionary) or None if the REST call fails
        """

        logger.info("Start synchronization of workspace -> '%s'...", workspace_name)

        license_post_body_json = f"""<SOAP:Envelope xmlns:SOAP=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n" +
		"	<SOAP:Body>\r\n" +
		"		<Synchronize workspaceID=\"{workspace_id}\" xmlns=\"http://schemas.cordys.com/cws/synchronize/1.0\" >\r\n" +
		"			<DocumentID/>\r\n" +
		"			<Asynchronous>false</Asynchronous>\r\n" +
		"		</Synchronize>\r\n" +
		"	</SOAP:Body>\r\n" +
		"</SOAP:Envelope>"""
        # self.authenticate(revalidate=True)

        retries = 0
        while True:
            response = requests.post(
                url=self.gateway_url(),
                data=license_post_body_json,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info("Workspace -> '%s' synced successfully", workspace_name)
                return self.parse_xml(response.text)
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def publish_project(
            self,
            workspace_name: str,
            project_name: str,
            workspace_id: str,
            project_id: str
        ) -> dict | bool:
        """
        Publish the workspace project.

        Args:
            workspace_name (str): The name of the workspace.
            project_name (str): The name of the project.
            workspace_id (str): The workspace ID.
            project_id (str): The project ID.

        Returns:
            dict | bool: Request response (dictionary) if successful, False if it fails after retries.
        """

        logger.info(
            "Publish project -> '%s' in workspace -> '%s'...",
            project_name,
            workspace_name,
        )

        project_publish = f"""<SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP:Body>
                <deployObject xmlns="http://schemas.cordys.com/cws/internal/buildhelper/BuildHelper/1.0" async="false" workspaceID="{workspace_id}" xmlns:c="http://schemas.cordys.com/cws/1.0">
                    <object>
                        <c:uri id="{project_id}"/>
                    </object>
                </deployObject>
            </SOAP:Body>
        </SOAP:Envelope>"""

        # Initialize retry parameters
        max_retries = 10
        retries = 0
        success_indicator = "deployObjectResponse"

        while retries < max_retries:
            response = requests.post(
                url=self.gateway_url(),
                data=project_publish,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )

            # Check if the response is successful
            if response.ok:
                # Check if the response contains the success indicator
                if success_indicator in response.text:
                    logger.info(
                        "Successfully published project -> '%s' in workspace -> '%s'",
                        project_name,
                        workspace_name,
                    )
                    return True

                # If success indicator is not found, retry
                logger.warning(
                    "Expected success indicator -> '%s' but it was not found in response. Retrying in 30 seconds... (Attempt %d of %d)",
                    success_indicator,
                    retries + 1,
                    max_retries,
                )
                time.sleep(30)
                retries += 1
                continue

            # Check for session expiry and retry authentication (only once)
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - re-authenticating...")
                self.authenticate(revalidate=True)
                retries += 1
                continue

            # Log any other error and break the loop
            logger.error(
                "Error publishing project -> '%s' in workspace -> '%s'; response -> %s",
                project_name,
                workspace_name,
                response.text,
            )
            break

        # After reaching the maximum number of retries, log failure and return False
        logger.error(
            "Max retries reached. Failed to publish project -> '%s' in workspace -> '%s'.",
            project_name,
            workspace_name,
        )
        return False

    # end method definition

    def create_priority(
        self,
        name: str,
        description: str,
        status: int
    ) -> dict | None:
        """ Create Priority entity instances.

        Args:
            name (str): name
            description (str): description
            status (int): status
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """
        create_priority = {
            "Properties": {
                "Name": name,
                "Description": description,
                "Status": status
            }
        }
        retries = 0
        while True:
            response = requests.post(
                url=self.create_priority_url(),
                json=create_priority,
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info("Priority created successfully")
                return self.parse_request_response(
                    response, "This can be normal during restart", False
                )
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def get_all_priorities(
        self
    ) -> dict | None:
        """ Get all priorities from entity
        Args:
            None
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """
        retries = 0
        while True:
            response = requests.get(
                url=self.get_all_priorities_url(),
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                authenticate_dict = self.parse_request_response(
                response, "This can be normal during restart", False
                )
                if not authenticate_dict:
                    return None
                return authenticate_dict
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def create_customer(
        self,
        customer_name: str,
        legal_business_name: str,
        trading_name: str
    ) -> dict | None:
        """ Create customer entity instance

        Args:
            customer_name (str): customer_name
            legal_business_name (str): legal_business_name
            trading_name (str): trading_name
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """
        create_customer = {
            "Properties": {
            "CustomerName": customer_name,
            "LegalBusinessName": legal_business_name,
            "TradingName": trading_name
            }
        }
        retries = 0
        while True:
            response = requests.post(
                url=self.create_customer_url(),
                json=create_customer,
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info("Customer record created successfully")
                return  self.parse_request_response(response, "This can be normal during restart", False)
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def get_all_customers(
        self
    ) -> dict | None:
        """get all customer entity imstances

        Args:
            None
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """

        retries = 0
        while True:
            response = requests.get(
                url=self.get_all_customeres_url(),
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                authenticate_dict = self.parse_request_response(
                response, "This can be normal during restart", False
                )
                if not authenticate_dict:
                    return None
                return  authenticate_dict
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def create_case_type(
        self,
        name: str,
        description: str,
        status: int
    ) -> dict | None:
        """create case_type entity instances

        Args:
            name (str): name
            description (str): description
            status (str): status
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """
        create_case_type = {
            "Properties": {
            "Name": name,
            "Description": description,
            "Status": status
            }
        }
        retries = 0
        while True:
            response = requests.post(
                url=self.create_casetype_url(),
                json=create_case_type,
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info("Case type created successfully")
                return self.parse_request_response(
                    response, "This can be normal during restart", False
                )
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def get_all_case_type(
        self
    ) -> dict | None:
        """get all case type entty instances

        Args:
            None
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """
        retries = 0
        while True:
            response = requests.get(
                url=self.get_all_case_types_url(),
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                authenticate_dict = self.parse_request_response(
                response, "This can be normal during restart", False
                )
                if not authenticate_dict:
                    return None
                return authenticate_dict
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def create_category(
        self,
        case_prefix: str,
        description: str,
        name: str,
        status: int
    ) -> dict | None:
        """create category entity instance

        Args:
            case_prefix (str): workspace_name
            description (str): description
            name (str): name
            status (str): status
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """
        create_categoty = {
            "Properties": {
            "CasePrefix": case_prefix,
            "Description": description,
            "Name": name,
            "Status": status
            }
        }
        retries = 0
        while True:
            response = requests.post(
                url=self.create_category_url(),
                json=create_categoty,
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info("Category created successfully")
                return  self.parse_request_response(response, "This can be normal during restart", False)
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def get_all_categories(
        self
    ) -> dict | None:
        """Get all categories entity intances

        Args:
            None
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """

        retries = 0
        while True:
            response = requests.get(
                url=self.get_all_categories_url(),
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                authenticate_dict = self.parse_request_response(
                response, "This can be normal during restart", False
                )
                if not authenticate_dict:
                    return None
                return  authenticate_dict
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def create_sub_categoy(
        self,
        name: str,
        description: str,
        status: int,
        parentid: int
    ) -> dict | None:
        """ create sub_categoy entity istances

        Args:
            name (str): name
            description (str): description
            status (int): status
            parentid (int): parentid
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """
        create_sub_categoty = {
            "Properties": {
            "Name": name,
            "Description": description,
            "Status": status
            }
        }
        retries = 0
        while True:
            base_url = self.baseurl()
            endpoint = "/app/entityRestService/api/OpentextCaseManagement/entities/Category/items/"
            child_path = "/childEntities/SubCategory?defaultinst_ct=abcd"
            response = requests.post(
                url=base_url + endpoint + str(parentid) + child_path,
                json=create_sub_categoty,
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info("Sub category created successfully")
                return self.parse_request_response(
                    response, "This can be normal during restart", False
                )
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def get_all_sub_categeries(
        self,
        parentid: int
    ) -> dict | None:
        """Get all sub categeries entity instances

        Args:
            parentid (int): parentid
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """
        retries = 0
        while True:
            base_url = self.baseurl()
            endpoint = "/app/entityRestService/api/OpentextCaseManagement/entities/Category/items/"
            child_path = "/childEntities/SubCategory"
            response = requests.get(
                url=base_url + endpoint + str(parentid) + child_path,
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                authenticate_dict = self.parse_request_response(
                response, "This can be normal during restart", False
                )
                if not authenticate_dict:
                    return None
                return  authenticate_dict
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def create_loan(
        self,
        subject: str,
        description: str,
        loan_amount: str,
        loan_duration_in_months: str,
        category: str,
        subcategory: str,
        piority: str,
        service: str,
        customer: str

    ) -> dict | None:
        """create loan entity instance

        Args:
            subject (str): subject
            description (str): description
            loan_amount (str): loan_amount
            loan_duration_in_months (str): loan_duration_in_months
            category (str): category
            subcategory (str): subcategory
            piority (str): piority
            service (str): service
            customer (str): customer
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """
        create_loan = f"""<SOAP:Envelope xmlns:SOAP=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n
  <SOAP:Body>\r\n
    <CreateCase xmlns=\"http://schemas/OpentextCaseManagement/Case/operations\">\r\n
      <ns0:Case-create xmlns:ns0=\"http://schemas/OpentextCaseManagement/Case\">\r\n
        <ns0:Subject>{subject}</ns0:Subject>\r\n
        <ns0:Description>{description}</ns0:Description>\r\n
        <ns0:LoanAmount>{loan_amount}</ns0:LoanAmount>\r\n
        <ns0:LoanDurationInMonths>{loan_duration_in_months}</ns0:LoanDurationInMonths>\r\n
        \r\n
        <ns0:CaseType>\r\n
          <ns1:CaseType-id xmlns:ns1=\"http://schemas/OpentextCaseManagement/CaseType\">\r\n
            <ns1:Id>{service}</ns1:Id>\r\n
          </ns1:CaseType-id>\r\n
        </ns0:CaseType>\r\n
        \r\n
        <ns0:Category>\r\n
          <ns2:Category-id xmlns:ns2=\"http://schemas/OpentextCaseManagement/Category\">\r\n
            <ns2:Id>{category}</ns2:Id>\r\n
          </ns2:Category-id>\r\n
        </ns0:Category>\r\n
        \r\n
        <ns0:SubCategory>\r\n
          <ns5:SubCategory-id xmlns:ns5=\"http://schemas/OpentextCaseManagement/Category.SubCategory\">\r\n
            <ns5:Id>{category}</ns5:Id>\r\n
            <ns5:Id1>{subcategory}</ns5:Id1>\r\n
          </ns5:SubCategory-id>\r\n
        </ns0:SubCategory>\r\n
        \r\n
        <ns0:Priority>\r\n
          <ns3:Priority-id xmlns:ns3=\"http://schemas/OpentextCaseManagement/Priority\">\r\n
            <ns3:Id>{piority}</ns3:Id>\r\n
          </ns3:Priority-id>\r\n
        </ns0:Priority>\r\n
\r\n
        <ns0:ToCustomer>\r\n
          <ns9:Customer-id xmlns:ns9=\"http://schemas/OpentextCaseManagement/Customer\">\r\n
            <ns9:Id>{customer}</ns9:Id>\r\n
          </ns9:Customer-id>\r\n
        </ns0:ToCustomer>\r\n
\r\n
      </ns0:Case-create>\r\n
    </CreateCase>\r\n
  </SOAP:Body>\r\n
</SOAP:Envelope>"""

        retries = 0
        while True:
            response = requests.post(
                url=self.gateway_url(),
                data=create_loan,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info("Loan created successfully")
                return  self.parse_xml(response.text)
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            logger.error(response.text)
            return None

    # end method definition

    def get_all_loan(
        self
    ) -> dict | None:
        """get all loan entity instances

        Args:
           None
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """

        retries = 0
        while True:
            response = requests.get(
                url=self.get_all_loans_url(),
                headers=REQUEST_HEADERS_JSON,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                authenticate_dict = self.parse_request_response(
                response, "This can be normal during restart", False
                )
                if not authenticate_dict:
                    return None
                return authenticate_dict
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            else:
                logger.error(response.text)
                return None

    # end method definition

    def validate_workspace_response(
            self,
            response: str,
            workspace_name: str
        ) -> bool:
        """
        Verify if the workspace exists or was created successfully.

        Args:
            response (str): response to validate
            workspace_name (str): The name of the workspace.

        Returns:
            bool: True if the workspace exists or was created successfully, else False.
        """

        if "Object already exists" in response or "createWorkspaceResponse" in response:
            logger.info(
                "The workspace already exists or was created with the name -> '%s'",
                workspace_name,
            )
            return True

        logger.info(
            "The workspace -> '%s' does not exist or was not created. Please verify configurtion!",
            workspace_name,
        )
        return False

    # end method definition

    def is_workspace_already_exists(
        self,
        response: str,
        workspace_name: str
    ) -> bool:
        """verify is workspace exists
        Args:
            workspace_name (str): workspace_name
        Returns:
            bool: return true if workspace exist else return false
        """

        if "Object already exists" in response:
            logger.info(
                "The workspace already exists with the name -> '%s'", workspace_name
            )
            return True
        logger.info(
            "The Workspace has been created with the name -> '%s'", workspace_name
        )
        return False

    # end method definition

    def create_workspace_with_retry(self, workspace_name: str, workspace_gui_id: str) -> dict | None:
        """
        Calls create_workspace and retries if the response contains specific error messages.
        Retries until the response does not contain the errors or a max retry limit is reached.
        """

        max_retries = 20  # Define the maximum number of retries
        retries = 0
        error_messages = [
            "Collaborative Workspace Service Container is not able to handle the SOAP request",
            "Service Group Lookup failure"
        ]

        while retries < max_retries:
            response = self.create_workspace(workspace_name, workspace_gui_id)

            # Check if any error message is in the response
            if any(error_message in response for error_message in error_messages):
                logger.info("Workspace service error, waiting 60 seconds to retry... (Retry %d of %d)", retries + 1, max_retries)
                time.sleep(60)
                retries += 1
            else:
                logger.info("Collaborative Workspace Service Container is ready")
                return response

        # After max retries, log and return the response or handle as needed
        logger.error(
            "Max retries reached for workspace -> '%s', unable to create successfully.",
            workspace_name,
        )
        return response

    # end method definition

    def loan_management_runtime(self) -> dict | None:
        """it will create all runtime objects for loan management application
        Args:
            None
        Returns:
            None
        """

        logger.debug(" RUNTIME -->> Category instance creation started ........ ")
        category_resp_dict = []
        if not self.verify_category_exists("Short Term Loan"):
            self.create_category("LOAN","Short Term Loan","Short Term Loan",1)
        if not self.verify_category_exists("Long Term Loan"):
            self.create_category("LOAN","Long Term Loan","Long Term Loan",1)
        if not self.verify_category_exists("Flexi Loan"):
            self.create_category("LOAN","Flexi Loan","Flexi Loan",1)
        category_resp_dict = self.get_category_lists()
        logger.debug(" RUNTIME -->> Category instance creation ended")

        ############################# Sub category
        logger.debug(" RUNTIME -->> Sub Category instance creation started ........")
        stl = 0
        ltl = 0
        fl = 0
        if not self.verify_sub_category_exists("Business",0,category_resp_dict):
            response_dict =  self.create_sub_categoy("Business","Business",1,category_resp_dict[0])
            stl = response_dict["Identity"]["Id"]
            logger.info("Sub category id stl:  %s ", stl)
        else:
            stl = self.return_sub_category_exists_id("Business",0,category_resp_dict)
            logger.info("Sub category id stl -> %s ", stl)

        if not self.verify_sub_category_exists("Business",1,category_resp_dict):
            response_dict=self.create_sub_categoy("Business","Business",1,category_resp_dict[1])
            ltl = response_dict["Identity"]["Id"]
            logger.info("Sub category id ltl -> %s ", ltl)
        else:
            ltl = self.return_sub_category_exists_id("Business",1,category_resp_dict)
            logger.info("Sub category id ltl -> %s ", ltl)
        if not self.verify_sub_category_exists("Business",2,category_resp_dict):
            response_dict= self.create_sub_categoy("Business","Business",1,category_resp_dict[2])
            fl = response_dict["Identity"]["Id"]
            logger.info("Sub category id fl -> %s ", fl)
        else:
            fl = self.return_sub_category_exists_id("Business",2,category_resp_dict)
            logger.info("Sub category id fl -> %s ", fl)
        logger.debug(" RUNTIME -->> Sub Category instance creation ended")

        ############################# Case Types
        logger.debug(" RUNTIME -->> Case Types instance creation started ........")
        case_type_list = []

        if not self.vverify_case_type_exists("Query"):
            self.create_case_type("Query","Query",1)
        if not self.vverify_case_type_exists("Help"):
            self.create_case_type("Help","Help",1)
        if not self.vverify_case_type_exists("Update Contact Details"):
            self.create_case_type("Update Contact Details","Update Contact Details",1)
        if not self.vverify_case_type_exists("New Loan Request"):
            self.create_case_type("New Loan Request","New Loan Request",1)
        if not self.vverify_case_type_exists("Loan Closure"):
            self.create_case_type("Loan Closure","Loan Closure",1)
        case_type_list = self.get_case_type_lists()
        logger.debug(" RUNTIME -->> Case Types instance creation ended")

        ############################# CUSTMOR
        logger.debug(" RUNTIME -->> Customer instance creation stated ........")
        customer_list = []
        if not self.verify_customer_exists("InaPlex Limited"):
            self.create_customer("InaPlex Limited","InaPlex Limited","InaPlex Limited")

        if not self.verify_customer_exists("Interwoven, Inc"):
            self.create_customer("Interwoven, Inc","Interwoven, Inc","Interwoven, Inc")

        if not self.verify_customer_exists("Jones Lang LaSalle"):
            self.create_customer("Jones Lang LaSalle","Jones Lang LaSalle","Jones Lang LaSalle")

        if not self.verify_customer_exists("Key Point Consulting"):
            self.create_customer("Key Point Consulting","Key Point Consulting","Key Point Consulting")

        customer_list = self.get_customer_lists()
        logger.debug(" RUNTIME -->> Customer instance creation ended")

        ######################################## PRIORITY
        logger.debug(" RUNTIME -->> priority instance creation started ........")
        prioity_list = []
        if not self.verify_priority_exists("High"):
            self.create_priority("High","High",1)
        if not self.verify_priority_exists("Medium"):
            self.create_priority("Medium","Medium",1)
        if not self.verify_priority_exists("Low"):
            self.create_priority("Low","Low",1)
        prioity_list = self.get_priority_lists()
        logger.debug(" RUNTIME -->> priority instance creation ended")

        ############################# LOAN
        loan_for_business = "Loan for Business1"
        loan_for_corporate_business = "Loan for Corporate Business1"
        loan_for_business_loan_request = "Loan for Business Loan Request1"

        logger.debug(" RUNTIME -->> loan instance creation started ........")
        loan_resp_dict = self.get_all_loan()
        names = [item["Properties"]["Subject"] for item in loan_resp_dict["_embedded"]["AllCasesList"]]
        if loan_for_business in names:
            logger.info("Customer record Loan_for_business exists")
        else:
            logger.info("Creating customer Record with Loan_for_business ")
            response_dict = self.create_loan(
                loan_for_business,
                loan_for_business,
                1,
                2,
                category_resp_dict[0],
                stl,
                prioity_list[0],
                case_type_list[0],
                customer_list[0],
            )

        if loan_for_corporate_business in names:
            logger.info("Customer record Loan_for_Corporate_Business exists")
        else:
            logger.info("Creating customer Record with Loan_for_Corporate_Business ")
            response_dict = self.create_loan(
                loan_for_corporate_business,
                loan_for_corporate_business,
                1,
                2,
                category_resp_dict[1],
                ltl,
                prioity_list[1],
                case_type_list[1],
                customer_list[1],
            )

        if loan_for_business_loan_request in names:
            logger.info("Customer record Loan_for_business_Loan_Request exists")
        else:
            logger.info("Creating customer Record with loan_for_business_loan_request")
            response_dict = self.create_loan(
                loan_for_business_loan_request,
                loan_for_business_loan_request,
                1,
                2,
                category_resp_dict[2],
                fl,
                prioity_list[2],
                case_type_list[2],
                customer_list[2],
            )
        logger.debug(" RUNTIME -->> loan instance creation ended")

    # end method definition

    def get_category_lists(self) -> list:
        """get All category entty instances id's
        Args:
            None
        Returns:
            list: list of category IDs
        """

        category_resp_dict = []
        categoy_resp_dict = self.get_all_categories()
        for item in categoy_resp_dict["_embedded"]["CategoryList"]:
            first_item_href = item["_links"]["item"]["href"]
            integer_value = int(re.search(r'\d+', first_item_href).group())
            logger.info("Category created with ID -> %d", integer_value)
            category_resp_dict.append(integer_value)
        logger.info("All extracted category IDs -> %s", category_resp_dict)

        return category_resp_dict

    # end method definition

    def get_case_type_lists(self) -> list:
        """Get All CaseType entity instances IDs
        Args:
            None
        Returns:
            list: list contains CaseType IDs
        """

        case_type_list = []
        casetype_resp_dict = self.get_all_case_type()
        for item in casetype_resp_dict["_embedded"]["AllCaseTypes"]:
            first_item_href = item["_links"]["item"]["href"]
            integer_value = int(re.search(r'\d+', first_item_href).group())
            logger.info("Case type created with ID -> %d", integer_value)
            case_type_list.append(integer_value)
        logger.info("All extracted case type IDs -> %s", case_type_list)

        return case_type_list

    # end method definition

    def get_customer_lists(self) -> list:
        """Get all customer entity instances id's
        Args:
            None
        Returns:
            list: list of customer IDs
        """

        customer_list = []
        customer_resp_dict = self.get_all_customers()
        for item in customer_resp_dict["_embedded"]["CustomerList"]:
            first_item_href = item["_links"]["item"]["href"]
            integer_value = int(re.search(r'\d+', first_item_href).group())
            logger.info("Customer created with ID -> %d", integer_value)
            customer_list.append(integer_value)
        logger.info("All extracted Customer IDs -> %s ", customer_list)
        return customer_list

    # end method definition

    def get_priority_lists(self) -> list:
        """get all priority entity instances IDs
        Args:
            None
        Returns:
            list: list contains priority IDs
        """

        prioity_list = []
        authenticate_dict = self.get_all_priorities()
        for item in authenticate_dict["_embedded"]["PriorityList"]:
            first_item_href = item["_links"]["item"]["href"]
            integer_value = int(re.search(r'\d+', first_item_href).group())
            logger.info("Priority created with ID -> %d", integer_value)
            prioity_list.append(integer_value)
        logger.info("All extracted priority IDs -> %s  ", prioity_list)

        return prioity_list

    # end method definition

    def verify_category_exists(self, name: str) -> bool:
        """verify category entity instance already exists
        Args:
            name (str): name of the category
        Returns:
            bool: returns True if already record exists with same name, else returns False
        """

        categoy_resp_dict = self.get_all_categories()
        names = [item["Properties"]["Name"] for item in categoy_resp_dict["_embedded"]["CategoryList"]]
        if name in names:
            logger.info("Category record -> '%s' already exists", name)
            return True
        logger.info("Creating category record -> '%s'", name)

        return False

    # end method definition

    def vverify_case_type_exists(self, name: str) -> bool:
        """verify case type entity instance already exists
        Args:
            name (str): name of the case type
        Returns:
            bool: returns True if already record exists with same name, else returns False
        """

        casetype_resp_dict = self.get_all_case_type()
        names = [item["Properties"]["Name"] for item in casetype_resp_dict["_embedded"]["AllCaseTypes"]]
        if name in names:
            logger.info("Case type record -> '%s' already exists", name)
            return True
        logger.info("Creating case type record -> '%s'", name)

        return False

    # end method definition

    def verify_customer_exists(self, name: str) -> bool:
        """verify cusomer entty instance already exists
        Args:
            name (str): name of the customer
        Returns:
            bool: returns True if already record exists with same name, else returns False
        """
        customer_resp_dict = self.get_all_customers()
        names = [item["Properties"]["CustomerName"] for item in customer_resp_dict["_embedded"]["CustomerList"]]
        if name in names:
            logger.info("Customer -> '%s' already exists", name)
            return True
        logger.info("Creating customer -> '%s'", name)
        return False

    # end method definition

    def verify_priority_exists(self, name: str) -> bool:
        """verify piority entity instance already exists
        Args:
            name (str): name of the priority
        Returns:
            bool: returns True if already record exists with same name, else returns False
        """

        authenticate_dict = self.get_all_priorities()
        names = [item["Properties"]["Name"] for item in authenticate_dict["_embedded"]["PriorityList"]]
        if name in names:
            logger.info("Priority -> '%s' already exists", name)
            return True
        logger.info("Creating priority -> '%s'", name)

        return False

    # end method definition

    def verify_sub_category_exists(self, name: str, index: int, category_resp_dict: list) -> bool:
        """verify sub category entity instance already exists
        Args:
            name (str): name of the sub category
        Returns:
            bool: returns true if record already exists with same name, else returns false
        """

        subcategoy_resp_dict = self.get_all_sub_categeries(category_resp_dict[index])
        names = [item["Properties"]["Name"] for item in subcategoy_resp_dict["_embedded"]["SubCategory"]]
        stl=0
        if name in names:
            logger.info("Sub category -> '%s' already exists", name)
            for item in subcategoy_resp_dict["_embedded"]["SubCategory"]:
                stl = item["Identity"]["Id"]
                logger.info("Sub category created with ID -> %s", stl)
                return True
        logger.info("Creating sub category -> '%s'", name)

        return False

    # end method definition

    def return_sub_category_exists_id(self, name: str, index: int, category_resp_dict: list) -> int:
        """verify sub category entity instance id already exists
        Args:
            name (str): name of the sub-category
        Returns:
            bool: returns true if record already exists with same name, else returns false
        """

        subcategoy_resp_dict = self.get_all_sub_categeries(category_resp_dict[index])
        names = [item["Properties"]["Name"] for item in subcategoy_resp_dict["_embedded"]["SubCategory"]]
        stl=0
        if  name in names:
            logger.info("Sub category record -> '%s' already exists", name)
            for item in subcategoy_resp_dict["_embedded"]["SubCategory"]:
                stl = item["Identity"]["Id"]
                logger.info("Sub category created with ID -> %s", stl)
                return stl

        return None

    # end method definition

    def create_users_from_config_file(self, otawpsection: str, _otds: OTDS):
        """read user information from customizer file and call create user method
        Args:
            otawpsection (str): yaml bock related to appworks
        Returns:
            None
        """

        otds = otawpsection.get("otds", {})
        if otds is not None:
            users = otds.get("users", [])
            if users is not None:
                for user in users:
                    _otds.add_user(
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
                            _otds.add_user_to_group(
                                user.get("name") + "@" + user.get("partition"),
                                # user.get('name'),
                                role.get("name"),
                            )
                    else:
                        logger.error(
                            "Verifying Users section: roles section not presented in yaml for otds users"
                        )
            else:
                logger.error(
                    "Verifying Users section: user section not presented in yaml"
                )
        else:
            logger.error("Verifying Users section: otds section not presented in yaml")

    # end method definition

    def create_roles_from_config_file(self, otawpsection: str, _otds: OTDS):
        """read grop information from customizer file and call create grop method
        Args:
            otawpsection (str): yaml bock related to appworks
            _otds (object): the OTDS object used to access the OTDS REST API
        Returns:
            None
        """

        otds = otawpsection.get("otds", {})
        if otds is not None:
            roles = otds.get("roles", [])
            if roles is not None:
                for role in roles:
                    # Add new group if it does not yet exist:
                    if not _otds.get_group(group=role.get("name"), show_error=False):
                        _otds.add_group(
                            role.get("partition"),
                            role.get("name"),
                            role.get("description"),
                        )
            else:
                logger.error(
                    "Verifying roles section: roles section not presented in yaml"
                )
        else:
            logger.error("Verifying roles section: otds section not presented in yaml")

    # end method definition

    def create_loanruntime_from_config_file(self, platform: str):
        """verify flag and call loan_management_runtime()
        Args:
            platform (str): yaml bock related to platform
        Returns:
            None
        """

        runtime = platform.get("runtime", {})
        if runtime is not None:
            app_names = runtime.get("appNames", [])
            if app_names is not None:
                for app_name in app_names:
                    if app_name == "loanManagement":
                        self.loan_management_runtime()
                    else:
                        logger.error(
                            "Verifying runtime section: loanManagement not exits in yaml entry"
                        )
            else:
                logger.error(
                    "Verifying runtime section: App name section is empty in yaml"
                )
        else:
            logger.error("Verifying runtime section: Runtime section is empty in yaml")

    # end method definition

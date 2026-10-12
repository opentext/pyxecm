# Copyright (C) 2024-2026, OpenText
"""SAP Module to talk to SAP S/4HANA via Remote Function Calls (RFC) and OData REST APIs.

The module supports two integration channels:

1. RFC (via PyRFC) - see call(). PyRFC is no longer maintained by SAP and requires
   the proprietary SAP NW RFC SDK. Use it only for existing RFC / BAPI use cases.
2. OData (via HTTPS) - see do_request(). This is the future-proof channel based on
   SAP's released APIs (SAP Business Accelerator Hub: https://api.sap.com).
   It requires the 'base_url' parameter of the SAP class.

OData specifics handled by this module:
* Basic authentication with the SAP user and password (or a custom requests auth
  object, e.g. a per-user bearer token - see the 'auth' parameter of the SAP class).
* Principal propagation (calls under the identity of the individual user): pyxecm acts
  as a minimal SAML 2.0 identity provider (get_saml_assertion()) and exchanges the
  assertion for an SAP OAuth 2.0 access token (get_oauth_access_token(), RFC 7522).
  See docs/pyxecm-customizer/sap-authentication.md for the SAP configuration.
* The readable error of the last failed request is available via 'last_error'.
* The SAP client ("Mandant") and the logon language are passed as query parameters
  ('sap-client' and 'sap-language') with every request.
* Modifying requests (POST, PUT, PATCH, MERGE, DELETE) get a CSRF token that is
  fetched and renewed automatically. It is bound to the SAP session cookies, so
  each thread uses its own requests.Session.

OData services must be activated in S/4HANA (verify with check_odata_apis()):
1. /IWFND/MAINT_SERVICE: "Add Service" -> backend system alias (e.g. LOCAL),
   technical service name (e.g. API_MAINTENANCEORDER) -> "Get Services" ->
   select the versions (0001, 0002) -> "Add Selected Services".
2. SICF: the ICF node /sap/opu/odata/sap/<service> must be active.
3. PFCG: authorization S_SERVICE for the service (role menu entry of type IWSG)
   plus business authorizations (e.g. as for IW31 to create maintenance orders).
4. /IWFND/GW_CLIENT: GET /sap/opu/odata/sap/<service>/$metadata returns 200.
Errors: /IWFND/ERROR_LOG and SU53. OData V4 services: /IWFND/V4_ADMIN.

OData services used by this module (see SAP_ODATA_SERVICES) - they have to be activated
(OData V2) or published (OData V4) in the SAP Gateway of the S/4HANA system before the
corresponding methods can be used. check_odata_apis() checks all of them.

OData V2 - activate in /IWFND/MAINT_SERVICE ("Add Service", see above):
* Plant Maintenance: API_MAINTENANCEORDER (version 0002), API_MAINTNOTIFICATION,
  API_MAINTORDERCONFIRMATION, API_MAINTENANCEPLAN
* Sales: API_SALES_ORDER_SRV, API_SALES_CONTRACT_SRV
* Purchasing: API_PURCHASECONTRACT_PROCESS_SRV
* Inventory Management: API_MATERIAL_DOCUMENT_SRV
* Production: API_PRODUCTION_ORDER_2_SRV
* Master data: API_PRODUCT_SRV, API_STORAGELOCATION_SRV, API_WORK_CENTERS,
  API_EQUIPMENT, API_FUNCTIONALLOCATION, API_BUSINESS_PARTNER, API_COMPANYCODE_SRV,
  API_SALESORGANIZATION_SRV, API_COSTCENTER_SRV, API_PROFITCENTER_SRV,
  API_GLACCOUNTINCHARTOFACCOUNTS_SRV

OData V4 - publish the service group in /IWFND/V4_ADMIN ("Publish Service Groups"),
the ICF node /sap/opu/odata4 must be active and S_SERVICE is granted per service group
(role menu entry "TADIR Service" R3TR G4BA <service group>):
* Purchasing: API_PURCHASEORDER_2, API_PURCHASEREQUISITION_2
* Production: API_PLANNEDORDER
* Master data: API_PLANT_2, API_PRODUCTION_VERSION, API_PURCHASINGORGANIZATION

SAP documentation of the OData APIs used by this module:
* SAP Business Accelerator Hub - API_MAINTENANCEORDER (properties, EDMX):
  https://api.sap.com/api/API_MAINTENANCEORDER/overview
* SAP Help - Maintenance Order (deprecated in S/4HANA Cloud 2308):
  https://help.sap.com/docs/SAP_S4HANA_CLOUD/f9ba73d1b8c543c2bd2ba1666271af86/d3f02cfccf00407ab9776ea2ec2030d3.html
* SAP Help - Maintenance Order (Version 2), the successor (OData V2, ;v=0002):
  https://help.sap.com/docs/SAP_S4HANA_CLOUD/f9ba73d1b8c543c2bd2ba1666271af86/c1457e0e539740a29932fbdcf36fea3c.html
* SAP Help - Create Maintenance Order Operation:
  https://help.sap.com/docs/SAP_S4HANA_CLOUD/f9ba73d1b8c543c2bd2ba1666271af86/7dbab77fa358454caa4289bc057cf66d.html
* SAP Help - Maintenance Order API (S/4HANA on-premise):
  https://help.sap.com/docs/SAP_S4HANA_ON-PREMISE/9a02a02d849d4b38a7320d94a71d2a22/f3521b71f69b4cbf81ab21a7c2c01527.html
* Metadata of a system: <base_url>/sap/opu/odata/sap/API_MAINTENANCEORDER/$metadata

For documentation of PyRFC see here: https://github.com/SAP/PyRFC
and here: https://sap.github.io/PyRFC/pyrfc.html

RFC typically uses port 3300 to communicate with the SAP server.
Make sure this port is not blocked by your firewall.

Connection Parameter:
* ashost (hostname or IP address of the application server - this should NOT be a full URL!)
* sysnr (the backend's system number, e.g. 00)
* client (the client or "Mandant" to which to logon, e.g. 100)
* user (e.g. "nwheeler")
* passwd (password of the user)
* lang (logon language as two-character ISO-Code, e.g. EN)
* trace (one of 0(off), 1(brief), 2(verbose), 3(detailed), 4(full))
* use_tls (activates SSL/TLS encryption. Set to 0 or 1. By default TLS is turned on (1))
* tls_client_pse (Specifies the PSE file containing the necessary certificates for TLS communication.
                  A PSE file is a SAP proprietary certificate store, similar to a p12 file,
                  containing the private key and the certificate chain to be used in the TLS
                  handshake with the server, beginning with the server's public certificate and
                  ending with the root CA certificate. It should also contain the client certificate
                  used for login at the server, if your client program does not use basic
                  user & password authentication)
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2026, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import base64
import json
import logging
import platform
import re
import sys
import threading
import time
import urllib.parse
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from http import HTTPStatus
from importlib.metadata import version

import requests
from lxml import etree
from pydantic import BaseModel, ValidationError

from .sap_models import (
    SAPBusinessPartnerQueryModel,
    SAPBusinessPartnerResponseModel,
    SAPCompanyCodeQueryModel,
    SAPCompanyCodeResponseModel,
    SAPCostCenterQueryModel,
    SAPCostCenterResponseModel,
    SAPCustomerQueryModel,
    SAPEquipmentQueryModel,
    SAPEquipmentResponseModel,
    SAPFunctionalLocationQueryModel,
    SAPFunctionalLocationResponseModel,
    SAPGLAccountQueryModel,
    SAPGLAccountResponseModel,
    SAPGoodsMovementModel,
    SAPGoodsMovementQueryModel,
    SAPGoodsMovementResponseModel,
    SAPMaintenanceNotificationAction,
    SAPMaintenanceNotificationModel,
    SAPMaintenanceNotificationQueryModel,
    SAPMaintenanceNotificationResponseModel,
    SAPMaintenanceOrderAction,
    SAPMaintenanceOrderConfirmationModel,
    SAPMaintenanceOrderConfirmationQueryModel,
    SAPMaintenanceOrderConfirmationResponseModel,
    SAPMaintenanceOrderModel,
    SAPMaintenanceOrderQueryModel,
    SAPMaintenanceOrderResponseModel,
    SAPMaintenancePlanAction,
    SAPMaintenancePlanModel,
    SAPMaintenancePlanQueryModel,
    SAPMaintenancePlanResponseModel,
    SAPODataCreateModel,
    SAPODataErrorModel,
    SAPODataQueryModel,
    SAPODataServiceModel,
    SAPODataServiceState,
    SAPODataServiceStatusModel,
    SAPPlannedOrderModel,
    SAPPlannedOrderQueryModel,
    SAPPlannedOrderResponseModel,
    SAPPlantQueryModel,
    SAPPlantResponseModel,
    SAPProductionOrderAction,
    SAPProductionOrderModel,
    SAPProductionOrderQueryModel,
    SAPProductionOrderResponseModel,
    SAPProductionVersionQueryModel,
    SAPProductionVersionResponseModel,
    SAPProductQueryModel,
    SAPProductResponseModel,
    SAPProfitCenterQueryModel,
    SAPProfitCenterResponseModel,
    SAPPurchaseContractModel,
    SAPPurchaseContractQueryModel,
    SAPPurchaseContractResponseModel,
    SAPPurchaseOrderModel,
    SAPPurchaseOrderQueryModel,
    SAPPurchaseOrderResponseModel,
    SAPPurchaseRequisitionModel,
    SAPPurchaseRequisitionQueryModel,
    SAPPurchaseRequisitionResponseModel,
    SAPPurchasingOrganizationQueryModel,
    SAPPurchasingOrganizationResponseModel,
    SAPSalesContractModel,
    SAPSalesContractQueryModel,
    SAPSalesContractResponseModel,
    SAPSalesOrderModel,
    SAPSalesOrderQueryModel,
    SAPSalesOrderResponseModel,
    SAPSalesOrganizationQueryModel,
    SAPSalesOrganizationResponseModel,
    SAPStorageLocationQueryModel,
    SAPStorageLocationResponseModel,
    SAPVendorQueryModel,
    SAPWorkCenterQueryModel,
    SAPWorkCenterResponseModel,
    odata_literal,
)

default_logger = logging.getLogger("pyxecm_customizer.sap")

try:
    import pyrfc

    _has_pyrfc = True

except ModuleNotFoundError:
    default_logger.debug("pyrfc not installed, SAP integration impacted")
    _has_pyrfc = False

except ImportError:
    default_logger.debug("pyrfc could not be loaded, SAP integration impacted")
    _has_pyrfc = False

try:
    # signxml depends on cryptography, so both are available with the 'saml' extra:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from signxml import XMLSigner
    from signxml.algorithms import CanonicalizationMethod
    from signxml.exceptions import SignXMLException

    _has_signxml = True

except ModuleNotFoundError:
    default_logger.debug("signxml not installed, get_saml_assertion() is not available (install the 'saml' extra)")
    _has_signxml = False

except ImportError:
    default_logger.debug("signxml not available, get_saml_assertion() is not available (install the 'saml' extra)")
    _has_signxml = False


APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".sap"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

REQUEST_JSON_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# Token endpoint of the SAP OAuth 2.0 authorization server and the grant type
# to exchange a SAML 2.0 bearer assertion for an access token (RFC 7522):
OAUTH_TOKEN_PATH = "/sap/bc/sec/oauth2/token"
OAUTH_SAML2_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer"

# SAML 2.0 assertions minted by get_saml_assertion() (SAML 2.0 Core, RFC 7522):
SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
SAML_NAMEID_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
SAML_NAMEID_FORMAT_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
SAML_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# An assertion is used once, right after it is minted - so it is short-lived:
SAML_DEFAULT_VALIDITY_SECONDS = 120
SAML_MAX_VALIDITY_SECONDS = 300
# Assertions are valid from this many seconds in the past, for SAP clocks that run behind:
SAML_CLOCK_SKEW_SECONDS = 60
SAML_MIN_KEY_SIZE = 2048
# Warn at startup if the signing certificate expires within this many days:
SAML_CERTIFICATE_EXPIRY_WARNING_DAYS = 30

REQUEST_TIMEOUT = 60.0
REQUEST_MAX_RETRIES = 3
# Initial delay for exponential backoff on transient errors. It doubles
# per retry but is capped at REQUEST_RETRY_DELAY:
REQUEST_RETRY_BACKOFF = 1.0
REQUEST_RETRY_DELAY = 30.0

# HTTP methods that change data in SAP and thus require a CSRF token:
CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "MERGE", "DELETE"}
# HTTP methods that can safely be repeated if the outcome of a request is unknown
# (e.g. read timeout). A POST that timed out may still have created the object in
# SAP - repeating it could create a duplicate (e.g. a second maintenance order):
IDEMPOTENT_METHODS = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}
# Status codes that indicate a transient server-side problem. For idempotent
# methods we retry on all of them. For non-idempotent methods we retry only on
# codes where SAP (or the load balancer) guarantees the request was NOT processed:
REQUEST_RETRY_STATUS_CODES_IDEMPOTENT = {429, 502, 503, 504}
REQUEST_RETRY_STATUS_CODES_NON_IDEMPOTENT = {429, 503}

# Regular expressions to determine the service root of an OData URL. The service
# root is used to fetch the CSRF token. Examples:
# V2: https://s4.example.com/sap/opu/odata/sap/API_MAINTENANCEORDER/MaintenanceOrder
# V4: https://s4.example.com/sap/opu/odata4/sap/<group>/srvd_a2x/sap/<service>/0001/<entity set>
ODATA_V2_SERVICE_ROOT_PATTERN = re.compile(r"^(.*?/sap/opu/odata/[^/]+/[^/?]+)")
ODATA_V4_SERVICE_ROOT_PATTERN = re.compile(r"^(.*?/sap/opu/odata4/(?:[^/]+/){5}\d{4})")


# Registry of the OData services this module uses. Extend this if
# new SAP APIs are supported by the SAP class:
SAP_ODATA_SERVICES: dict[str, SAPODataServiceModel] = {
    "API_MAINTENANCEORDER": SAPODataServiceModel(
        name="API_MAINTENANCEORDER",
        # Version 0002 ("Maintenance Order (Version 2)") is the successor of the
        # deprecated version 0001 - both are identical for the fields we use:
        path="/sap/opu/odata/sap/API_MAINTENANCEORDER;v=0002",
        odata_version=2,
        entity_sets=["MaintenanceOrder", "MaintenanceOrderOperation"],
        description="Plant Maintenance - Maintenance Order (Create, Read, Update)",
    ),
    # RAP based service, published as OData V2 (service binding API_MAINTNOTIFICATION, version 0001):
    "API_MAINTNOTIFICATION": SAPODataServiceModel(
        name="API_MAINTNOTIFICATION",
        path="/sap/opu/odata/sap/API_MAINTNOTIFICATION",
        odata_version=2,
        entity_sets=["MaintenanceNotification", "MaintenanceNotificationItem"],
        description="Plant Maintenance - Maintenance Notification (Create, Read, Update)",
    ),
    "API_SALES_ORDER_SRV": SAPODataServiceModel(
        name="API_SALES_ORDER_SRV",
        path="/sap/opu/odata/sap/API_SALES_ORDER_SRV",
        odata_version=2,
        entity_sets=["A_SalesOrder", "A_SalesOrderItem"],
        description="Sales - Sales Order (Create, Read, Update, Delete)",
    ),
    "API_SALES_CONTRACT_SRV": SAPODataServiceModel(
        name="API_SALES_CONTRACT_SRV",
        path="/sap/opu/odata/sap/API_SALES_CONTRACT_SRV",
        odata_version=2,
        entity_sets=["A_SalesContract", "A_SalesContractItem"],
        description="Sales - Sales Contract (Create, Read, Update, Delete)",
    ),
    # Version 0001 matches the published SAP metadata for this API. The system also has
    # version 0002 (";v=0002") - compare both with check_odata_apis() after activation:
    "API_PURCHASECONTRACT_PROCESS_SRV": SAPODataServiceModel(
        name="API_PURCHASECONTRACT_PROCESS_SRV",
        path="/sap/opu/odata/sap/API_PURCHASECONTRACT_PROCESS_SRV",
        odata_version=2,
        entity_sets=["A_PurchaseContract", "A_PurchaseContractItem"],
        description="Purchasing - Purchase Contract (Create, Read, Update)",
    ),
    # OData V4 successor of the V2 API API_PURCHASEREQ_PROCESS_SRV (service group
    # API_PURCHASEREQUISITION_2, service "PurchaseRequisition", version 0001):
    "API_PURCHASEREQUISITION_2": SAPODataServiceModel(
        name="API_PURCHASEREQUISITION_2",
        path="/sap/opu/odata4/sap/api_purchaserequisition_2/srvd_a2x/sap/purchaserequisition/0001",
        odata_version=4,
        entity_sets=["PurchaseReqn", "PurchaseReqnItem", "PurchaseReqnAcctAssgmt"],
        description="Purchasing - Purchase Requisition (Create, Read, Update)",
    ),
    "API_MATERIAL_DOCUMENT_SRV": SAPODataServiceModel(
        name="API_MATERIAL_DOCUMENT_SRV",
        path="/sap/opu/odata/sap/API_MATERIAL_DOCUMENT_SRV",
        odata_version=2,
        entity_sets=["A_MaterialDocumentHeader", "A_MaterialDocumentItem"],
        description="Inventory Management - Goods Movement / Material Document (Create, Read, Cancel)",
    ),
    # RAP based services, published as OData V2:
    "API_MAINTORDERCONFIRMATION": SAPODataServiceModel(
        name="API_MAINTORDERCONFIRMATION",
        path="/sap/opu/odata/sap/API_MAINTORDERCONFIRMATION",
        odata_version=2,
        entity_sets=["MaintOrderConfirmation"],
        description="Plant Maintenance - Maintenance Order Confirmation (Create, Read, Cancel)",
    ),
    "API_MAINTENANCEPLAN": SAPODataServiceModel(
        name="API_MAINTENANCEPLAN",
        path="/sap/opu/odata/sap/API_MAINTENANCEPLAN",
        odata_version=2,
        entity_sets=["MaintenancePlan", "MaintenancePlanCycle", "MaintenanceItem"],
        description="Plant Maintenance - Maintenance Plan (Create, Read, Update, Scheduling)",
    ),
    # Successor of the V2 API API_PLANNED_ORDERS (service group API_PLANNEDORDER, service
    # "PlannedOrder", version 0001):
    "API_PLANNEDORDER": SAPODataServiceModel(
        name="API_PLANNEDORDER",
        path="/sap/opu/odata4/sap/api_plannedorder/srvd_a2x/sap/plannedorder/0001",
        odata_version=4,
        entity_sets=["PlannedOrderHeader"],
        description="Production Planning - Planned Order (Create, Read, Update, Delete, Schedule)",
    ),
    "API_PRODUCTION_ORDER_2_SRV": SAPODataServiceModel(
        name="API_PRODUCTION_ORDER_2_SRV",
        path="/sap/opu/odata/sap/API_PRODUCTION_ORDER_2_SRV",
        odata_version=2,
        entity_sets=["A_ProductionOrder_2", "A_ProductionOrderOperation_2", "A_ProductionOrderStatus_2"],
        description="Production Planning - Production Order (Create, Read, Update, Convert, Status)",
    ),
    # Master data APIs (used read only):
    "API_PLANT_2": SAPODataServiceModel(
        name="API_PLANT_2",
        path="/sap/opu/odata4/sap/api_plant_2/srvd_a2x/sap/plant/0001",
        odata_version=4,
        entity_sets=["Plant"],
        description="Master Data - Plant (Read)",
    ),
    "API_STORAGELOCATION_SRV": SAPODataServiceModel(
        name="API_STORAGELOCATION_SRV",
        path="/sap/opu/odata/sap/API_STORAGELOCATION_SRV",
        odata_version=2,
        entity_sets=["StorageLocation"],
        description="Master Data - Storage Location (Read)",
    ),
    "API_PRODUCT_SRV": SAPODataServiceModel(
        name="API_PRODUCT_SRV",
        path="/sap/opu/odata/sap/API_PRODUCT_SRV",
        odata_version=2,
        entity_sets=["A_Product", "A_ProductPlant", "A_ProductDescription"],
        description="Master Data - Product / Material (Read)",
    ),
    "API_PRODUCTION_VERSION": SAPODataServiceModel(
        name="API_PRODUCTION_VERSION",
        path="/sap/opu/odata4/sap/api_production_version/srvd_a2x/sap/productionversion/0001",
        odata_version=4,
        entity_sets=["ProductionVersion"],
        description="Master Data - Production Version (Read)",
    ),
    "API_WORK_CENTERS": SAPODataServiceModel(
        name="API_WORK_CENTERS",
        path="/sap/opu/odata/sap/API_WORK_CENTERS",
        odata_version=2,
        entity_sets=["A_WorkCenters"],
        description="Master Data - Work Center (Read)",
    ),
    "API_EQUIPMENT": SAPODataServiceModel(
        name="API_EQUIPMENT",
        path="/sap/opu/odata/sap/API_EQUIPMENT",
        odata_version=2,
        entity_sets=["Equipment"],
        description="Master Data - Equipment (Read)",
    ),
    "API_FUNCTIONALLOCATION": SAPODataServiceModel(
        name="API_FUNCTIONALLOCATION",
        path="/sap/opu/odata/sap/API_FUNCTIONALLOCATION",
        odata_version=2,
        entity_sets=["FunctionalLocation"],
        description="Master Data - Functional Location (Read)",
    ),
    "API_BUSINESS_PARTNER": SAPODataServiceModel(
        name="API_BUSINESS_PARTNER",
        path="/sap/opu/odata/sap/API_BUSINESS_PARTNER",
        odata_version=2,
        entity_sets=["A_BusinessPartner", "A_BusinessPartnerRole"],
        description="Master Data - Business Partner (Read)",
    ),
    "API_COMPANYCODE_SRV": SAPODataServiceModel(
        name="API_COMPANYCODE_SRV",
        path="/sap/opu/odata/sap/API_COMPANYCODE_SRV",
        odata_version=2,
        entity_sets=["A_CompanyCode"],
        description="Master Data - Company Code (Read)",
    ),
    "API_SALESORGANIZATION_SRV": SAPODataServiceModel(
        name="API_SALESORGANIZATION_SRV",
        path="/sap/opu/odata/sap/API_SALESORGANIZATION_SRV",
        odata_version=2,
        entity_sets=["A_SalesOrganization"],
        description="Master Data - Sales Organization (Read)",
    ),
    "API_PURCHASINGORGANIZATION": SAPODataServiceModel(
        name="API_PURCHASINGORGANIZATION",
        path="/sap/opu/odata4/sap/api_purchasingorganization/srvd_a2x/sap/purchasingorganization/0001",
        odata_version=4,
        entity_sets=["A_PurchasingOrganization"],
        description="Master Data - Purchasing Organization (Read)",
    ),
    "API_COSTCENTER_SRV": SAPODataServiceModel(
        name="API_COSTCENTER_SRV",
        path="/sap/opu/odata/sap/API_COSTCENTER_SRV",
        odata_version=2,
        entity_sets=["A_CostCenter"],
        description="Master Data - Cost Center (Read)",
    ),
    "API_PROFITCENTER_SRV": SAPODataServiceModel(
        name="API_PROFITCENTER_SRV",
        path="/sap/opu/odata/sap/API_PROFITCENTER_SRV",
        odata_version=2,
        entity_sets=["A_ProfitCenter"],
        description="Master Data - Profit Center (Read)",
    ),
    "API_GLACCOUNTINCHARTOFACCOUNTS_SRV": SAPODataServiceModel(
        name="API_GLACCOUNTINCHARTOFACCOUNTS_SRV",
        path="/sap/opu/odata/sap/API_GLACCOUNTINCHARTOFACCOUNTS_SRV",
        odata_version=2,
        entity_sets=["A_GLAccountInChartOfAccounts"],
        description="Master Data - G/L Account in Chart of Accounts (Read)",
    ),
    # OData V4 successor of the deprecated V2 API API_PURCHASEORDER_PROCESS_SRV. The URL is
    # derived from the service binding (service group API_PURCHASEORDER_2, service "PurchaseOrder",
    # version 0001). The service group must be published in /IWFND/V4_ADMIN:
    "API_PURCHASEORDER_2": SAPODataServiceModel(
        name="API_PURCHASEORDER_2",
        path="/sap/opu/odata4/sap/api_purchaseorder_2/srvd_a2x/sap/purchaseorder/0001",
        odata_version=4,
        entity_sets=[
            "PurchaseOrder",
            "PurchaseOrderItem",
            "PurchaseOrderScheduleLine",
            "PurchaseOrderAccountAssignment",
        ],
        description="Purchasing - Purchase Order (Create, Read, Update, Delete)",
    ),
}

# OData V4 transmits Edm.Decimal values (quantities, prices) as JSON numbers by default.
# With IEEE754Compatible=true they are transmitted as strings, which avoids any loss of
# precision and matches Python's Decimal (pydantic serializes Decimal as string):
ODATA_V4_IEEE754_HEADERS = {
    "Accept": "application/json;IEEE754Compatible=true",
    "Content-Type": "application/json;IEEE754Compatible=true",
}

# $expand option to read purchase orders with their items, schedule lines and account assignments:
PURCHASE_ORDER_EXPAND_ITEMS = "_PurchaseOrderItem($expand=_PurchaseOrderScheduleLineTP,_PurOrdAccountAssignment)"
# $expand option to read purchase requisitions with their items and account assignments:
PURCHASE_REQUISITION_EXPAND_ITEMS = "_PurchaseRequisitionItem($expand=_PurchaseReqnAcctAssgmt)"

# Namespace of the bound actions of the OData V4 planned order API (RAP services use
# "com.sap.gateway.srvd_a2x.<service definition>.v<version>"):
PLANNED_ORDER_ACTION_NAMESPACE = "com.sap.gateway.srvd_a2x.api_plannedorder.v0001"


class _ODataReadError(Exception):
    """Internal signal that reading an OData collection failed (the error has been logged already)."""


class SAPODataIterator[T: BaseModel](Iterator[T]):
    """Iterator over the entities of an SAP OData collection (e.g. maintenance orders).

    The entities are read page by page while iterating - only one page is held in
    memory at a time, so even very large collections can be processed. Errors are
    logged and end the iteration; afterwards the attribute 'failed' tells whether
    the iteration ended because of an error (True) or because all entities have
    been read (False).

    Example:
        >>> orders = sap.iter_maintenance_orders(query=SAPMaintenanceOrderQueryModel(planning_plant="3000"))
        >>> for order in orders:
        ...     print(order.order_id, order.description)
        >>> if orders.failed:
        ...     print("Not all orders could be read!")

    """

    def __init__(self, entities: Iterator[T]) -> None:
        """Initialize the iterator.

        Args:
            entities (Iterator[T]):
                The underlying generator that reads the entities page by page.

        """

        self._entities = entities
        self.failed = False

    # end method definition

    def __next__(self) -> T:
        """Return the next entity (reading the next page from SAP if required).

        Returns:
            T:
                The next entity.

        Raises:
            StopIteration:
                If all entities have been read or an error occurred (see 'failed').

        """

        try:
            return next(self._entities)
        except _ODataReadError:
            self.failed = True
            raise StopIteration from None

    # end method definition


class BearerAuth(requests.auth.AuthBase):
    """Authenticate OData requests with an SAP OAuth 2.0 access token ("Authorization: Bearer").

    Used for principal propagation: pass it as the 'auth' parameter of an SAP object, so
    that all OData calls of this object run as the user the token was issued for.

    Example:
        >>> token = idp_sap.get_oauth_access_token_for_user(user_id="jane.smith@example.com", ...)
        >>> user_sap = SAP(username="", password="", system_id="S4H", base_url=..., auth=BearerAuth(token["access_token"]))

    The token is not renewed - create a new SAP object (with a new token) before it expires
    ('expires_in' of the token response). Each user needs an SAP object of their own, as SAP
    binds its session cookies and CSRF tokens to the user.

    """

    def __init__(self, access_token: str) -> None:
        """Initialize the authentication with an SAP access token.

        Args:
            access_token (str):
                The "access_token" of a token response of get_oauth_access_token().

        """

        self._access_token = access_token

    # end method definition

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the access token to a request (called by requests for every request).

        Args:
            request (requests.PreparedRequest):
                The request to authenticate.

        Returns:
            requests.PreparedRequest:
                The request with the "Authorization" header.

        """

        request.headers["Authorization"] = "Bearer " + self._access_token

        return request

    # end method definition


class SAP:
    """Implement Remote Function Calls (RFC) and OData REST API calls to SAP S/4HANA."""

    logger: logging.Logger = default_logger

    def __init__(
        self,
        username: str,
        password: str,
        system_id: str,
        ashost: str = "",
        mshost: str = "",
        msport: str = "3601",
        group: str = "PUBLIC",
        destination: str = "",
        client: str = "100",
        system_number: str = "00",
        lang: str = "EN",
        trace: str = "3",
        base_url: str = "",
        verify_ssl: bool = True,
        auth: requests.auth.AuthBase | None = None,
        saml_idp_private_key: str | None = None,
        saml_idp_certificate: str | None = None,
        saml_issuer: str = "",
        saml_audience: str = "",
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the SAP object.

        Args:
            username (str):
                The SAP user name (used for RFC and OData).
            password (str):
                The password of the SAP user (used for RFC and OData).
            system_id (str):
                The SAP system ID (RFC only).
            ashost (str, optional):
                Hostname of the application server for direct application server logon (RFC only).
            mshost (str, optional):
                Hostname of the message server for logon with load balancing (RFC only).
            msport (str, optional):
                Port of the message server (RFC only). Defaults to "3601".
            group (str, optional):
                Logon group for logon with load balancing (RFC only). Defaults to "PUBLIC".
            destination (str, optional):
                RFC destination (RFC only).
            client (str, optional):
                The SAP client ("Mandant"), used for RFC and OData. Defaults to "100".
            system_number (str, optional):
                The SAP system number (RFC only). Defaults to "00".
            lang (str, optional):
                The logon language (used for RFC and OData). Defaults to "EN".
            trace (str, optional):
                The RFC trace level (RFC only). Defaults to "3".
            base_url (str, optional):
                Base URL of the SAP system for OData REST API calls, e.g.
                "https://s4.example.com:44300". Required to use the OData methods
                like do_request(), check_odata_apis() or create_maintenance_order().
            verify_ssl (bool, optional):
                Whether to verify the TLS certificate of the SAP system for OData calls.
                Disable only for test systems with self-signed certificates. Defaults to True.
            auth (requests.auth.AuthBase | None, optional):
                Authentication for OData calls that replaces the basic authentication with
                username and password, e.g. a bearer token of the individual user obtained
                via principal propagation (OAuth 2.0 SAML bearer assertion). RFC calls are
                not affected. Defaults to None (basic authentication).
            saml_idp_private_key (str | None, optional):
                PEM-encoded, unencrypted RSA private key (at least 2048 bits) of pyxecm's
                SAML 2.0 identity provider. It signs the assertions of get_saml_assertion()
                for principal propagation into SAP (SAML 2.0 Bearer Assertion grant, RFC 7522).
                Whoever holds this key can obtain an SAP access token for every SAP user the
                SAP-side NameID mapping reaches - keep it in a secret store. The key pair is
                created once per deployment (see docs/pyxecm-customizer/sap-authentication.md),
                it is not generated by pyxecm. The key, the certificate, saml_issuer and
                saml_audience are validated here; if anything is wrong an error is logged
                and get_saml_assertion() refuses to mint assertions. Requires the 'saml'
                extra of pyxecm. Defaults to None (principal propagation disabled).
            saml_idp_certificate (str | None, optional):
                PEM-encoded X.509 certificate of saml_idp_private_key. The SAP administrator
                imports it as the signing certificate of the trusted identity provider in
                transaction SAML2. It is also embedded in the assertion's signature
                (ds:KeyInfo). Recommended - it is checked against the private key at startup
                and its expiry date also before each assertion. Defaults to None (no embedded
                certificate).
            saml_issuer (str, optional):
                The <saml:Issuer> of the assertions = the entity ID (provider name) of
                pyxecm's identity provider as registered in transaction SAML2, e.g.
                "pyxecm-idp". Required if saml_idp_private_key is given. Defaults to "".
            saml_audience (str, optional):
                The <saml:Audience> of the assertions = the provider name of the SAP system's
                local SAML 2.0 provider (transaction SAML2, "Local Provider" tab, e.g.
                "S4HCLNT100"). SAP rejects assertions for other audiences. Required if
                saml_idp_private_key is given. Defaults to "".
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("sap")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        self.logger.info("Initializing SAP object...")

        if _has_pyrfc:
            self.logger.info("Using PyRFC version -> %s", pyrfc.__version__)
        elif base_url:
            self.logger.info("PyRFC not installed. RFC calls are not possible - only OData REST API calls.")
        else:
            self.logger.warning("PyRFC not installed. Cannot talk to SAP!")

        # Set up OData connection parameters:
        self._base_url = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._auth = auth
        self._client = client
        self._lang = lang
        self._verify_ssl = verify_ssl
        # SAML 2.0 identity provider for principal propagation (see get_saml_assertion()).
        # Key, certificate and names are validated once here, so configuration errors
        # show up at startup and not with the first user request:
        self._saml_issuer = saml_issuer
        self._saml_audience = saml_audience
        self._saml_idp_private_key = None
        self._saml_idp_certificate = None
        # Checked with every assertion - a long-running process must not sign with an expired certificate:
        self._saml_idp_certificate_expiry = None
        self._saml_config_error = "the SAP object has been initialized without a saml_idp_private_key"
        if saml_idp_private_key:
            certificate = None
            if not _has_signxml:
                self._saml_config_error = "the 'signxml' package is not installed (install the 'saml' extra of pyxecm)"
            elif not saml_issuer or not saml_audience:
                self._saml_config_error = "saml_issuer and saml_audience are required"
            else:
                try:
                    private_key = serialization.load_pem_private_key(
                        saml_idp_private_key.encode("utf-8"), password=None
                    )
                    if saml_idp_certificate:
                        certificate = x509.load_pem_x509_certificate(saml_idp_certificate.encode("utf-8"))
                except (ValueError, TypeError, UnsupportedAlgorithm) as key_error:
                    # TypeError is raised for encrypted keys (no password given):
                    self._saml_config_error = "cannot load saml_idp_private_key or saml_idp_certificate ({})".format(
                        key_error
                    )
                else:
                    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < SAML_MIN_KEY_SIZE:
                        self._saml_config_error = (
                            "saml_idp_private_key must be an RSA key with at least {} bits".format(SAML_MIN_KEY_SIZE)
                        )
                    elif (
                        certificate
                        and certificate.public_key().public_numbers() != private_key.public_key().public_numbers()
                    ):
                        self._saml_config_error = "saml_idp_certificate does not belong to saml_idp_private_key"
                    elif certificate and certificate.not_valid_after_utc <= datetime.now(tz=UTC):
                        self._saml_config_error = "saml_idp_certificate expired on {}".format(
                            certificate.not_valid_after_utc.isoformat()
                        )
                    else:
                        self._saml_idp_private_key = private_key
                        self._saml_idp_certificate = saml_idp_certificate
                        self._saml_idp_certificate_expiry = certificate.not_valid_after_utc if certificate else None
                        self._saml_config_error = None
            if self._saml_config_error:
                self.logger.error("SAML 2.0 principal propagation is disabled - %s!", self._saml_config_error)
            else:
                self.logger.info(
                    "SAML 2.0 principal propagation is enabled (issuer -> '%s', audience -> '%s')",
                    saml_issuer,
                    saml_audience,
                )
                if certificate and certificate.not_valid_after_utc <= datetime.now(tz=UTC) + timedelta(
                    days=SAML_CERTIFICATE_EXPIRY_WARNING_DAYS
                ):
                    self.logger.warning(
                        "The SAML 2.0 signing certificate expires on %s - renew it and update the trust in SAP transaction SAML2!",
                        certificate.not_valid_after_utc.isoformat(),
                    )
        # Each thread gets its own requests.Session (with its own SAP session cookies
        # and CSRF tokens) as requests.Session objects are not thread-safe:
        self._thread_local = threading.local()

        if self._base_url:
            self.logger.info(
                "OData REST API calls are enabled for SAP system -> '%s' (client -> %s)", self._base_url, client
            )
            if not verify_ssl:
                self.logger.warning("TLS certificate verification for SAP OData calls is disabled!")

        # Set up connection parameters
        self._connection_parameters = {
            "user": username,
            "passwd": password,
            "client": client,
            "trace": trace,
            "lang": lang,
        }

        # see https://sap.github.io/PyRFC/pyrfc.html#connection
        if ashost:
            self.logger.info(
                "Logon with application server logon: requiring ashost, sysnr",
            )
            self._connection_parameters["ashost"] = ashost
            self._connection_parameters["sysnr"] = system_number
            self._connection_parameters["sysid"] = system_id
        elif mshost:
            self.logger.info(
                "Logon with load balancing: requiring mshost, msserv, sysid, group",
            )
            self._connection_parameters["mshost"] = mshost
            self._connection_parameters["sysid"] = system_id
            self._connection_parameters["msserv"] = msport
            self._connection_parameters["group"] = group

        if destination:
            self._connection_parameters["dest"] = destination

    # end method definition

    def call(self, rfc_name: str, options: dict, rfc_parameters: dict) -> dict | None:
        """Do an RFC Call.

        See http://sap.github.io/PyRFC/pyrfc.html#pyrfc.Connection.call

        Args:
            rfc_name (str):
                This is the name of the RFC (typical in capital letters), e.g. SM02_ADD_MESSAGE.
            options (dict):
                The call options for the RFC call. Potential options (keys):
                * not_requested:
                    Allows to deactivate certain parameters in the function module interface.
                    This is particularly useful for BAPIs which have many large tables, the Python client is not interested in.
                    Deactivate those, to reduce network traffic and memory consumption in your application considerably.
                    This functionality can be used for input and output parameters. If the parameter is an input,
                    no data for that parameter will be sent to the backend. If it's an output, the backend will be
                    informed not to return data for that parameter.
                * timeout:
                    Cancel RFC connection if ongoing RFC call not completed within timeout seconds.
                    Timeout can be also set as client connection configuration option, in which case is valid
                    for all RFC calls.
            rfc_parameters (dict):
                The actual RFC parameters that are specific for the type of the call.

        Returns:
            dict | None:
                Result of the RFC call or None if the call fails or times out.

        """

        # Create the connection object and call the RFC function
        params = self._connection_parameters
        self.logger.debug("Connection Parameters -> %s", params)

        try:
            with pyrfc.Connection(**params) as conn:
                result = conn.call(rfc_name, options=options, **rfc_parameters)
                return result
        except pyrfc.RFCError as sap_error:
            self.logger.error(
                "Failed to call RFC -> '%s'; error -> %s",
                rfc_name,
                str(sap_error),
            )
            return None

    # end method definition

    def request_session(self) -> requests.Session:
        """Return the calling thread's requests.Session for OData calls, creating it on first use.

        The session is pre-configured with authentication (basic or the auth object
        passed to the constructor), TLS verification,
        default JSON headers and the SAP client / language query parameters.
        In contrast to the OTCS class, the session keeps cookies: SAP binds the
        CSRF token to the session cookies, so they must be sent with every
        modifying request.

        Returns:
            requests.Session:
                A Session bound to the current thread.

        """

        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = requests.Session()
            session.auth = self._auth or (self._username, self._password)
            session.verify = self._verify_ssl
            session.headers.update(REQUEST_JSON_HEADERS)
            session.params = {"sap-client": self._client, "sap-language": self._lang}
            self._thread_local.session = session
            # CSRF tokens per OData service root (only valid with this session's cookies):
            self._thread_local.csrf_tokens = {}

        return session

    # end method definition

    @property
    def last_error(self) -> str | None:
        """Return the error of the calling thread's last failed OData request.

        The error is reset with each new request (do_request()), so it describes
        why the last method call (e.g. create_maintenance_order()) returned None
        or False. Useful to show SAP's own error message to users (or LLMs).

        Returns:
            str | None:
                The readable error (SAP message code, text and details) or None
                if the last request did not fail.

        """

        return getattr(self._thread_local, "last_error", None)

    # end method definition

    def log_error(self, message: str, *args: object) -> None:
        """Log an error and keep it as the error of the calling thread's last method call (see last_error).

        do_request() sets last_error for failed requests. Methods that fail without
        a failed request (e.g. invalid input data, an unexpected response) must use
        this method - otherwise last_error would still show the error of an earlier call.

        Args:
            message (str):
                The error message with %-style placeholders (like for logger.error()).
            *args (object):
                The values for the placeholders.

        """

        text = message % args if args else message
        self.logger.error(text)
        self._thread_local.last_error = text

    # end method definition

    def get_saml_assertion(
        self,
        user_id: str,
        nameid_format: str = SAML_NAMEID_FORMAT_UNSPECIFIED,
        recipient: str | None = None,
        audience: str | None = None,
        validity_seconds: int = SAML_DEFAULT_VALIDITY_SECONDS,
    ) -> str | None:
        """Mint and sign a SAML 2.0 bearer assertion for a user (pyxecm as SAML 2.0 identity provider).

        SAP's OAuth 2.0 server issues an access token for a user if it gets a SAML 2.0
        assertion for this user that is signed by a trusted identity provider (SAML 2.0
        Bearer Assertion grant, RFC 7522 - see get_oauth_access_token()). Neither OTDS
        (a SAML service provider only) nor SAP can issue such an assertion for an arbitrary
        user, so pyxecm acts as a minimal identity provider: this method builds the assertion
        and signs it with saml_idp_private_key (see the SAP class constructor).

        The assertion follows SAML 2.0 Core and the requirements of RFC 7522, section 3:
        * <saml:Issuer>: saml_issuer - the identity provider SAP trusts (transaction SAML2).
        * <ds:Signature>: enveloped XML signature (RSA-SHA256, SHA-256 digest, exclusive
          canonicalization) over the whole assertion, placed directly after the Issuer as
          the SAML schema requires. It embeds saml_idp_certificate if one is configured.
        * <saml:Subject>: the NameID user_id and a bearer SubjectConfirmation whose
          Recipient is SAP's token endpoint.
        * <saml:Conditions>: valid from SAML_CLOCK_SKEW_SECONDS in the past (tolerates
          clock differences) until validity_seconds from now, AudienceRestriction = the
          SAP system's local SAML 2.0 provider name.
        * <saml:AuthnStatement>: AuthnContextClassRef "unspecified" - pyxecm does not
          authenticate the user itself, the caller has done that.

        Security: the assertion grants SAP access as user_id. Only pass user IDs of users the
        calling application has authenticated (e.g. the user of a verified OTDS session) -
        never an unverified user ID from a request. Each minted assertion is logged with its
        ID, which also appears in SAP's SAML 2.0 trace.

        Args:
            user_id (str):
                The user to propagate - the assertion's NameID. SAP maps it to an SAP user as
                configured for the trusted identity provider in transaction SAML2 (e.g. via
                the SAP user ID, e-mail address or an alias, see nameid_format).
            nameid_format (str, optional):
                The NameID format - it must match the format configured in transaction SAML2
                ("Identity Federation" tab), e.g.
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" for e-mail addresses.
                Defaults to "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".
            recipient (str | None, optional):
                The token endpoint URL the assertion is posted to (SubjectConfirmationData
                Recipient). Defaults to None = "<base_url>/sap/bc/sec/oauth2/token". Only
                needed if SAP is reached via a different URL (e.g. a reverse proxy).
            audience (str | None, optional):
                The AudienceRestriction. Defaults to None = saml_audience of the constructor.
            validity_seconds (int, optional):
                Lifetime of the assertion in seconds (1 to SAML_MAX_VALIDITY_SECONDS = 300).
                Defaults to SAML_DEFAULT_VALIDITY_SECONDS = 120.

        Returns:
            str | None:
                The signed assertion as XML (for get_oauth_access_token(), which base64url-
                encodes it) or None if principal propagation is not configured correctly, the
                input is invalid or signing failed (see last_error).

        """

        self._thread_local.last_error = None

        if self._saml_idp_private_key is None:
            self.log_error("Cannot mint a SAML assertion - %s!", self._saml_config_error)
            return None

        # The certificate was valid at startup, but may have expired since - SAP would only answer
        # with a vague 'invalid_grant' then:
        if self._saml_idp_certificate_expiry and self._saml_idp_certificate_expiry <= datetime.now(tz=UTC):
            self.log_error(
                "Cannot mint a SAML assertion - saml_idp_certificate expired on %s! Renew it, update the trust "
                "in SAP transaction SAML2 and restart.",
                self._saml_idp_certificate_expiry.isoformat(),
            )
            return None

        if not recipient and not self._base_url:
            self.log_error("Cannot mint a SAML assertion - the SAP object has been initialized without a base URL!")
            return None

        if not user_id or user_id != user_id.strip():
            self.log_error(
                "Cannot mint a SAML assertion - the user ID -> '%s' is empty or has leading/trailing blanks!", user_id
            )
            return None

        if not 1 <= validity_seconds <= SAML_MAX_VALIDITY_SECONDS:
            self.log_error(
                "Cannot mint a SAML assertion - the validity -> %s must be between 1 and %s seconds!",
                validity_seconds,
                SAML_MAX_VALIDITY_SECONDS,
            )
            return None

        recipient = recipient or (self._base_url + OAUTH_TOKEN_PATH)
        audience = audience or self._saml_audience

        now = datetime.now(tz=UTC)
        issue_instant = now.strftime(SAML_TIME_FORMAT)
        not_before = (now - timedelta(seconds=SAML_CLOCK_SKEW_SECONDS)).strftime(SAML_TIME_FORMAT)
        not_on_or_after = (now + timedelta(seconds=validity_seconds)).strftime(SAML_TIME_FORMAT)
        # The ID must be an XML NCName (must not start with a digit):
        assertion_id = "_" + uuid.uuid4().hex

        def saml(tag: str) -> str:
            return "{{{}}}{}".format(SAML_ASSERTION_NS, tag)

        try:
            # lxml escapes all values (no XML injection) and raises ValueError for
            # characters that are not allowed in XML (e.g. control characters):
            assertion_el = etree.Element(
                saml("Assertion"),
                nsmap={"saml": SAML_ASSERTION_NS},
                attrib={"ID": assertion_id, "IssueInstant": issue_instant, "Version": "2.0"},
            )
            etree.SubElement(assertion_el, saml("Issuer")).text = self._saml_issuer
            # Placeholder that signxml replaces with the signature - the SAML schema requires
            # the signature directly after the Issuer (signxml would append it at the end):
            etree.SubElement(assertion_el, "{{{}}}Signature".format(XMLDSIG_NS), Id="placeholder")

            subject_el = etree.SubElement(assertion_el, saml("Subject"))
            etree.SubElement(subject_el, saml("NameID"), Format=nameid_format).text = user_id
            subject_confirmation_el = etree.SubElement(
                subject_el, saml("SubjectConfirmation"), Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"
            )
            # No NotBefore here - it is not allowed for bearer confirmations (SAML 2.0 Profiles, 4.1.4.2):
            etree.SubElement(
                subject_confirmation_el,
                saml("SubjectConfirmationData"),
                Recipient=recipient,
                NotOnOrAfter=not_on_or_after,
            )

            conditions_el = etree.SubElement(
                assertion_el, saml("Conditions"), NotBefore=not_before, NotOnOrAfter=not_on_or_after
            )
            audience_restriction_el = etree.SubElement(conditions_el, saml("AudienceRestriction"))
            etree.SubElement(audience_restriction_el, saml("Audience")).text = audience

            authn_statement_el = etree.SubElement(assertion_el, saml("AuthnStatement"), AuthnInstant=issue_instant)
            authn_context_el = etree.SubElement(authn_statement_el, saml("AuthnContext"))
            etree.SubElement(
                authn_context_el, saml("AuthnContextClassRef")
            ).text = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"

            signed_assertion_el = XMLSigner(
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
            ).sign(
                assertion_el,
                key=self._saml_idp_private_key,
                cert=self._saml_idp_certificate,
                reference_uri="#" + assertion_id,
            )
        except (ValueError, TypeError, SignXMLException) as error:
            self.log_error("Failed to mint SAML assertion for user -> '%s'; error -> %s", user_id, str(error))
            return None

        self.logger.info(
            "Minted SAML assertion -> '%s' for user -> '%s' (audience -> '%s', recipient -> '%s', valid until -> %s)",
            assertion_id,
            user_id,
            audience,
            recipient,
            not_on_or_after,
        )

        return etree.tostring(signed_assertion_el, encoding="unicode")

    # end method definition

    def get_oauth_access_token(
        self,
        assertion: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
    ) -> dict | None:
        """Exchange a SAML 2.0 bearer assertion of a user for an SAP OAuth 2.0 access token.

        This is the token request of the OAuth 2.0 SAML bearer assertion flow (RFC 7522)
        that SAP uses for principal propagation: SAP validates the assertion's signature
        against a trusted identity provider, maps its subject (NameID) to an SAP user and
        returns an access token for this user. OData calls with this token
        ("Authorization: Bearer <access_token>", see the 'auth' parameter of the SAP class)
        run with the SAP user's own authorizations - no SAP password of the user is needed.

        The request is sent as form data to <base_url>/sap/bc/sec/oauth2/token. It does
        not use the session of this object (the token endpoint authenticates the OAuth
        client, not the technical user).

        SAP prerequisites (the SAP S/4HANA administrator):
        1. SAML2: SAML 2.0 is enabled for the client and the issuer of the assertion is a
           trusted OAuth 2.0 identity provider (signing certificate + NameID mapping).
        2. SOAUTH2: an OAuth 2.0 client = an SU01 system user (client ID = user name, client
           secret = its password - not related to the end users)
           with grant type "SAML 2.0 Bearer Assertion" and the scopes of the OData services.
        3. /IWFND/MAINT_SERVICE: OAuth is enabled for the OData services (this also creates
           their scope IDs, e.g. "API_MAINTENANCEORDER_0002" for version 0002).

        Args:
            assertion (str):
                The signed SAML 2.0 assertion - the XML (it is base64url-encoded here) or an
                already base64url-encoded assertion. Its audience must be the SAML 2.0 provider
                name of the SAP system and its recipient the token endpoint URL.
            client_id (str):
                The OAuth 2.0 client ID registered in SOAUTH2 - the user name of the SU01
                system user that represents pyxecm as OAuth client.
            client_secret (str):
                The password of that system user (SOAUTH2 client authentication "Password").
                It authenticates pyxecm as the calling application - it is not the password
                of the end user the token is issued for.
            scope (str | None, optional):
                Space-separated scope IDs, e.g. "API_MAINTENANCEORDER_0002 API_MAINTNOTIFICATION_0001".
                Defaults to None (the default scopes of the OAuth client).

        Returns:
            dict | None:
                The token response or None if the request failed (see last_error). Example:
                {
                    "access_token": "j0F2nk...",
                    "token_type": "Bearer",
                    "expires_in": "3600",
                    "scope": "API_MAINTENANCEORDER_0002"
                }

        """

        self._thread_local.last_error = None

        if not self._base_url:
            self.log_error(
                "Cannot get an SAP OAuth access token - the SAP object has been initialized without a base URL!"
            )
            return None

        if assertion.lstrip().startswith("<"):
            assertion = base64.urlsafe_b64encode(assertion.strip().encode("utf-8")).decode("ascii").rstrip("=")

        token_url = self._base_url + OAUTH_TOKEN_PATH
        data = {"grant_type": OAUTH_SAML2_BEARER_GRANT_TYPE, "assertion": assertion, "client_id": client_id}
        if scope:
            data["scope"] = scope

        self.logger.debug("Requesting SAP OAuth access token for client -> '%s' from -> %s", client_id, token_url)

        try:
            response = requests.post(
                url=token_url,
                params={"sap-client": self._client},
                data=data,
                auth=(client_id, client_secret),
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                verify=self._verify_ssl,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as request_error:
            self.log_error(
                "Failed to request SAP OAuth access token from -> %s; error -> %s", token_url, str(request_error)
            )
            return None

        try:
            token = response.json()
        except ValueError:
            token = {}

        if not response.ok or "access_token" not in token:
            # SAP returns OAuth errors as {"error": "...", "error_description": "..."}:
            self.log_error(
                "Failed to get SAP OAuth access token for client -> '%s'; status -> %s/%s; error -> %s",
                client_id,
                response.status_code,
                response.reason,
                "{} - {}".format(token.get("error"), token.get("error_description"))
                if token.get("error")
                else response.text[:500],
            )
            return None

        self.logger.info(
            "Received SAP OAuth access token for client -> '%s'; scope -> '%s'; expires in -> %s seconds",
            client_id,
            token.get("scope", ""),
            token.get("expires_in", "?"),
        )

        return token

    # end method definition

    def get_oauth_access_token_for_user(
        self,
        user_id: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
        nameid_format: str = SAML_NAMEID_FORMAT_UNSPECIFIED,
    ) -> dict | None:
        """Get an SAP OAuth 2.0 access token for a user via principal propagation, in one call.

        Mints a fresh SAML 2.0 bearer assertion for user_id with get_saml_assertion() and
        exchanges it right away for an SAP access token with get_oauth_access_token() - see
        both methods for the prerequisites. Only pass user IDs of users the calling
        application has authenticated (see the security note of get_saml_assertion()).

        Args:
            user_id (str):
                The user to propagate - the assertion's NameID (see get_saml_assertion()).
            client_id (str):
                The OAuth 2.0 client ID registered in SOAUTH2 - the user name of the SU01
                system user that represents pyxecm as OAuth client.
            client_secret (str):
                The password of that system user (SOAUTH2 client authentication "Password").
                It authenticates pyxecm as the calling application - it is not the password
                of the end user the token is issued for.
            scope (str | None, optional):
                Space-separated scope IDs, e.g. "API_MAINTENANCEORDER_0002". Defaults to
                None (the default scopes of the OAuth client).
            nameid_format (str, optional):
                The NameID format - must match transaction SAML2 (see get_saml_assertion()).
                Defaults to "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".

        Returns:
            dict | None:
                The token response (see get_oauth_access_token()) or None if minting the assertion or the token request
                failed (see last_error).

        """

        assertion = self.get_saml_assertion(user_id=user_id, nameid_format=nameid_format)
        if not assertion:
            return None

        return self.get_oauth_access_token(
            assertion=assertion, client_id=client_id, client_secret=client_secret, scope=scope
        )

    # end method definition

    def service_url(self, service: str | SAPODataServiceModel) -> str:
        """Return the full URL of the root of an OData service.

        Args:
            service (str | SAPODataServiceModel):
                The service definition or the technical service name. Names
                that are not registered in SAP_ODATA_SERVICES are treated as
                OData V2 services with the standard path /sap/opu/odata/sap/<name>.

        Returns:
            str:
                The service root URL, e.g.
                "https://s4.example.com:44300/sap/opu/odata/sap/API_MAINTENANCEORDER".

        """

        if isinstance(service, str):
            service = SAP_ODATA_SERVICES.get(service) or SAPODataServiceModel(
                name=service,
                path="/sap/opu/odata/sap/{}".format(service),
            )

        return self._base_url + service.path

    # end method definition

    def csrf_token(self, url: str, refresh: bool = False) -> str | None:
        """Get a CSRF token for modifying OData requests to the service the URL belongs to.

        The token is fetched once per service root and thread and then cached.
        SAP returns it in the 'x-csrf-token' response header of a GET request
        that has the request header 'x-csrf-token: Fetch'.

        Args:
            url (str):
                Any URL of the OData service (the service root is derived from it).
            refresh (bool, optional):
                If True, a cached token is discarded and a new one is fetched.
                Used if SAP rejected the cached token. Defaults to False.

        Returns:
            str | None:
                The CSRF token or None if it could not be fetched.

        """

        session = self.request_session()
        csrf_tokens: dict[str, str] = self._thread_local.csrf_tokens

        # Determine the service root - this is where we fetch the token from:
        match = ODATA_V2_SERVICE_ROOT_PATTERN.match(url) or ODATA_V4_SERVICE_ROOT_PATTERN.match(url)
        service_root = match.group(1) if match else url.split("?", 1)[0]

        if not refresh and service_root in csrf_tokens:
            return csrf_tokens[service_root]

        self.logger.debug("Fetching CSRF token from SAP OData service -> '%s'...", service_root)

        try:
            response = session.get(
                url=service_root + "/",
                headers={"x-csrf-token": "Fetch"},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as request_error:
            self.log_error(
                "Failed to fetch CSRF token from SAP OData service -> '%s'; error -> %s",
                service_root,
                str(request_error),
            )
            return None

        token = response.headers.get("x-csrf-token")
        if not response.ok or not token or token.lower() == "required":
            self.log_error(
                "Failed to fetch CSRF token from SAP OData service -> '%s'; status -> %s/%s; error -> %s",
                service_root,
                response.status_code,
                response.reason,
                str(SAPODataErrorModel.from_response(response)) if not response.ok else "no token in response header",
            )
            return None

        csrf_tokens[service_root] = token
        self.logger.debug("Received CSRF token for SAP OData service -> '%s'.", service_root)

        return token

    # end method definition

    def parse_request_response(
        self,
        response_object: requests.Response,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Convert the text of a response object to a Python dict safely.

        Args:
            response_object (requests.Response):
                The response object delivered by the request call.
            additional_error_message (str, optional):
                Custom error message to include in logs. Defaults to "".
            show_error (bool, optional):
                If True, logs an error. If False, logs a warning. Defaults to True.

        Returns:
            dict | None:
                Parsed response as a dictionary (empty dict for responses without content,
                e.g. HTTP 204 for updates), or None if the response is not valid JSON.

        """

        if response_object is None:
            return None

        if not response_object.text:
            return {}

        try:
            return json.loads(response_object.text)
        except json.JSONDecodeError as exception:
            message = "Cannot decode SAP response as JSON{}; status -> {}; error -> {}".format(
                ". {}".format(additional_error_message) if additional_error_message else "",
                response_object.status_code,
                exception,
            )
            if show_error:
                self.logger.error(message)
            else:
                self.logger.warning(message)
            self.logger.debug("Response text -> %s", response_object.text)

            return None

    # end method definition

    def do_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        params: dict | None = None,
        json_data: dict | None = None,
        timeout: float | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        show_warning: bool = False,
        warning_message: str = "",
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        parse_request_response: bool = True,
        parse_error_response: bool = False,
    ) -> dict | requests.Response | None:
        """Call an SAP OData REST API in a safe way.

        This method takes care of:
        * Authentication, SAP client and language (via the request session).
        * Fetching and renewing CSRF tokens for modifying requests (POST, PUT, PATCH, MERGE, DELETE).
        * HTTP 401: if the SAP session has ended, a new session is started once (SAP has not
          processed the request, so this is safe for all methods). Otherwise last_error tells
          whether the credentials or - with the 'auth' parameter - the access token were rejected
          (e.g. an expired token of principal propagation, which this object cannot renew).
        * Retries with exponential backoff for transient errors (timeouts, connection errors,
          HTTP 429/502/503/504). Non-idempotent requests (POST, PATCH, MERGE) are only retried
          if it is certain that SAP did not process them (connect timeout, HTTP 429/503) -
          otherwise a retry could create duplicate objects in SAP.
        * Logging of readable error messages extracted from SAP's OData error responses.

        Args:
            url (str):
                The full URL to send the request to (use service_url() to build it).
            method (str, optional):
                HTTP method (GET, POST, PATCH, ...). Defaults to "GET".
            headers (dict | None, optional):
                Additional request headers (merged with the default JSON headers). Defaults to None.
            params (dict | None, optional):
                Additional query parameters, e.g. {"$filter": "...", "$top": 10}. Defaults to None.
            json_data (dict | None, optional):
                Request payload that is sent as JSON. Defaults to None.
            timeout (float | None, optional):
                Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed REST call.
                If False, a warning is logged if show_warning is True, otherwise only
                a debug message is logged. Defaults to True.
            show_warning (bool, optional):
                Whether or not a warning should be logged in case of a failed REST call.
                This is only evaluated if show_error is False. Defaults to False.
            warning_message (str, optional):
                Specific warning message. If not given, the failure_message will be used. Defaults to "".
            failure_message (str, optional):
                Specific error message. Defaults to "".
            success_message (str, optional):
                Specific success message. Defaults to "".
            max_retries (int, optional):
                Maximum number of retries for transient errors. Defaults to REQUEST_MAX_RETRIES.
            parse_request_response (bool, optional):
                Whether the response text should be interpreted as JSON and returned
                as a dictionary. If False, the requests.Response object is returned. Defaults to True.
            parse_error_response (bool, optional):
                Whether the error response should be returned as a dictionary (SAPODataErrorModel.model_dump())
                instead of None. Defaults to False.

        Returns:
            dict | requests.Response | None:
                The parsed response (dict), the response object (if parse_request_response is False),
                or None in case of an error (or the parsed error if parse_error_response is True).

        """

        # Readable error of this request for callers of the public methods (see last_error):
        self._thread_local.last_error = None

        if not self._base_url:
            self.logger.error(
                "Cannot call SAP OData API -> '%s' - the SAP object has been initialized without a base URL!",
                url,
            )
            self._thread_local.last_error = "SAP OData is not configured (no base URL)."
            return None

        method = method.upper()
        failure_message = failure_message or "Failed to call SAP OData API -> {} {}".format(method, url)
        request_headers = dict(headers) if headers else {}
        is_idempotent = method in IDEMPOTENT_METHODS
        requires_csrf_token = method in CSRF_PROTECTED_METHODS
        retry_status_codes = (
            REQUEST_RETRY_STATUS_CODES_IDEMPOTENT if is_idempotent else REQUEST_RETRY_STATUS_CODES_NON_IDEMPOTENT
        )
        retries = 0
        csrf_token_refreshed = False
        session_renewed = False

        while True:
            if requires_csrf_token:
                token = self.csrf_token(url=url)
                if not token:
                    self.logger.error("%s; cannot get a CSRF token!", failure_message)
                    return None
                request_headers["x-csrf-token"] = token

            self.logger.debug(
                "Calling SAP OData API -> %s %s (params -> %s, retry -> %d/%d)...",
                method,
                url,
                str(params),
                retries,
                max_retries,
            )

            try:
                response = self.request_session().request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    params=params,
                    json=json_data,
                    timeout=timeout,
                )
            except requests.exceptions.ConnectTimeout as connect_error:
                # The request never reached SAP - safe to retry for all methods:
                error_text = "connect timeout -> {}".format(connect_error)
                retry_allowed = True
            except requests.exceptions.ReadTimeout as read_error:
                # SAP received the request but did not answer in time. It may still have been processed!
                error_text = "read timeout -> {}".format(read_error)
                retry_allowed = is_idempotent
            except requests.exceptions.ConnectionError as connection_error:
                # Could happen before or after SAP processed the request - can't tell:
                error_text = "connection error -> {}".format(connection_error)
                retry_allowed = is_idempotent
            except requests.exceptions.RequestException as request_error:
                self.logger.error("%s; request error -> %s", failure_message, str(request_error))
                self._thread_local.last_error = "Request error -> {}".format(request_error)
                return None
            else:
                error_text = ""

            # Handle exceptions (no response received):
            if error_text:
                if retry_allowed and retries < max_retries:
                    retries += 1
                    backoff_delay = min(REQUEST_RETRY_BACKOFF * 2 ** (retries - 1), REQUEST_RETRY_DELAY)
                    self.logger.warning(
                        "%s; %s. Retrying in %s seconds... %d/%d",
                        failure_message,
                        error_text,
                        str(backoff_delay),
                        retries,
                        max_retries,
                    )
                    time.sleep(backoff_delay)
                    continue
                if not retry_allowed:
                    self.logger.error(
                        "%s; %s. Not retrying the non-idempotent %s request as SAP may have processed it already "
                        "(retrying could create duplicates). Please check in SAP if the request was processed!",
                        failure_message,
                        error_text,
                        method,
                    )
                else:
                    self.logger.error("%s; %s. Giving up after %d retries.", failure_message, error_text, retries)
                self._thread_local.last_error = "SAP is not reachable ({}).".format(error_text)
                return None

            # SAP may return additional (warning / info) messages in the 'sap-message' header:
            sap_message = response.headers.get("sap-message")
            if sap_message:
                self.logger.debug("SAP message -> %s", sap_message)

            if response.ok:
                if success_message:
                    self.logger.info(success_message)
                if not parse_request_response:
                    return response
                return self.parse_request_response(response_object=response, additional_error_message=failure_message)

            # The CSRF token has expired or the SAP session has ended - fetch a new token and try once more:
            if (
                response.status_code == HTTPStatus.FORBIDDEN
                and requires_csrf_token
                and not csrf_token_refreshed
                and response.headers.get("x-csrf-token", "").lower() == "required"
            ):
                self.logger.info("SAP rejected the CSRF token for -> '%s'. Fetching a new token and retrying...", url)
                csrf_token_refreshed = True
                if not self.csrf_token(url=url, refresh=True):
                    self.logger.error("%s; cannot renew the CSRF token!", failure_message)
                    return None
                continue

            # SAP rejected the authentication. If the request was sent with the cookies of an existing
            # SAP session, the session may have ended - drop its cookies and CSRF tokens and try once
            # more with the credentials alone. Without cookies, the credentials themselves were rejected
            # - no retry then, as each failed logon counts towards locking the SAP user:
            session = self.request_session()
            if response.status_code == HTTPStatus.UNAUTHORIZED and not session_renewed and session.cookies:
                self.logger.info(
                    "SAP rejected the session for -> '%s'. Starting a new SAP session and retrying...", url
                )
                session_renewed = True
                session.cookies.clear()
                self._thread_local.csrf_tokens.clear()
                continue

            # Transient server-side errors - retry with backoff (or the delay SAP asks for):
            if response.status_code in retry_status_codes and retries < max_retries:
                retries += 1
                retry_after = response.headers.get("Retry-After", "")
                backoff_delay = (
                    min(float(retry_after), REQUEST_RETRY_DELAY)
                    if retry_after.isdigit()
                    else min(REQUEST_RETRY_BACKOFF * 2 ** (retries - 1), REQUEST_RETRY_DELAY)
                )
                self.logger.warning(
                    "%s; status -> %s/%s. This is a transient error. Retrying in %s seconds... %d/%d",
                    failure_message,
                    response.status_code,
                    response.reason,
                    str(backoff_delay),
                    retries,
                    max_retries,
                )
                time.sleep(backoff_delay)
                continue

            # Permanent error:
            error = SAPODataErrorModel.from_response(response)
            if response.status_code == HTTPStatus.UNAUTHORIZED:
                # SAP answers 401 with an HTML page - say instead what was rejected and what to do:
                error.message = (
                    "SAP rejected the access token (expired or revoked) - get a new token and create a new SAP object"
                    if self._auth
                    else "SAP rejected user name or password of user -> '{}' (wrong password or user locked)".format(
                        self._username
                    )
                )
            self._thread_local.last_error = "HTTP {} - {}".format(response.status_code, error)
            if show_error:
                self.logger.error(
                    "%s; status -> %s/%s; error -> %s",
                    failure_message,
                    response.status_code,
                    response.reason,
                    str(error),
                )
            elif show_warning:
                self.logger.warning(
                    "%s; status -> %s/%s; warning -> %s",
                    warning_message or failure_message,
                    response.status_code,
                    response.reason,
                    str(error),
                )
            else:
                self.logger.debug(
                    "Status -> %s/%s; debug -> %s",
                    response.status_code,
                    response.reason,
                    str(error),
                )
            self.logger.debug("Full error response -> %s", response.text)

            return error.model_dump() if parse_error_response else None

        # end while True

    # end method definition

    def check_odata_apis(
        self,
        services: list[str | SAPODataServiceModel] | None = None,
        timeout: float = REQUEST_TIMEOUT,
    ) -> dict[str, SAPODataServiceStatusModel]:
        """Check if the required OData APIs are activated and usable in the S/4HANA system.

        For each service the service document (service root) is requested. The result is
        interpreted to distinguish the typical setup problems:
        * The service is not activated / published in SAP Gateway
          (/IWFND/MAINT_SERVICE for OData V2, /IWFND/V4_ADMIN for OData V4).
        * The ICF node of the OData endpoint is inactive (transaction SICF).
        * Authentication fails (wrong user, password or client) or the user lacks
          authorizations for the service (authorization object S_SERVICE).
        * The service is active but does not expose the expected entity sets
          (e.g. older S/4HANA release or a different service version).
        * The SAP system is not reachable at all (DNS, firewall, TLS, timeout).

        The check uses the request session directly (not do_request()) as it needs
        the raw status code of failed requests and should not retry.

        Args:
            services (list[str | SAPODataServiceModel] | None, optional):
                The services to check - either technical names or service definitions.
                Defaults to None which checks all services in SAP_ODATA_SERVICES.
            timeout (float, optional):
                Timeout for each check request in seconds. Defaults to REQUEST_TIMEOUT.

        Returns:
            dict[str, SAPODataServiceStatusModel]:
                The status per service name. Use status.active to check the result.
                Returns an empty dictionary if no base URL is configured.

        Example:
            >>> statuses = sap.check_odata_apis()
            >>> if not all(status.active for status in statuses.values()):
            ...     print("SAP is not ready for OData integration!")

        """

        if not self._base_url:
            self.logger.error("Cannot check SAP OData APIs - the SAP object has been initialized without a base URL!")
            return {}

        if services is None:
            services = list(SAP_ODATA_SERVICES.values())

        results: dict[str, SAPODataServiceStatusModel] = {}

        for service in services:
            if isinstance(service, str):
                service = SAP_ODATA_SERVICES.get(service) or SAPODataServiceModel(
                    name=service,
                    path="/sap/opu/odata/sap/{}".format(service),
                )
            # The trailing slash returns the service document (and avoids a redirect):
            url = self.service_url(service) + "/"
            activation_transaction = "/IWFND/MAINT_SERVICE" if service.odata_version == 2 else "/IWFND/V4_ADMIN"

            self.logger.info(
                "Checking SAP OData API -> '%s' (OData V%d) at -> %s ...",
                service.name,
                service.odata_version,
                url,
            )

            try:
                response = self.request_session().get(url=url, timeout=timeout)
            except requests.exceptions.SSLError as ssl_error:
                status = SAPODataServiceStatusModel(
                    service=service,
                    url=url,
                    state=SAPODataServiceState.UNREACHABLE,
                    message=str(ssl_error),
                    hint="TLS handshake failed. Check the certificate of the SAP system or set verify_ssl=False "
                    "for test systems with self-signed certificates.",
                )
            except requests.exceptions.RequestException as request_error:
                status = SAPODataServiceStatusModel(
                    service=service,
                    url=url,
                    state=SAPODataServiceState.UNREACHABLE,
                    message=str(request_error),
                    hint="Check the base URL (protocol, hostname, HTTPS port of the ICM - typically 443<NN>), "
                    "DNS resolution and firewall rules.",
                )
            else:
                status = self._evaluate_odata_service_response(
                    service=service,
                    url=url,
                    response=response,
                    activation_transaction=activation_transaction,
                )

            if status.active:
                self.logger.info(
                    "SAP OData API -> '%s' is active (entity sets -> %s).",
                    service.name,
                    ", ".join(service.entity_sets) or "not checked",
                )
            else:
                self.logger.error(
                    "SAP OData API -> '%s' is not usable; state -> '%s'; status -> %s; message -> %s; hint -> %s",
                    service.name,
                    status.state.value,
                    status.http_status if status.http_status is not None else "n/a",
                    status.message,
                    status.hint,
                )
                if status.available_entity_sets:
                    self.logger.info(
                        "Entity sets exposed by SAP OData API -> '%s': %s",
                        service.name,
                        ", ".join(status.available_entity_sets),
                    )

            results[service.name] = status

        active_count = sum(1 for status in results.values() if status.active)
        log_method = self.logger.info if active_count == len(results) else self.logger.warning
        log_method("%d of %d SAP OData API(s) are active.", active_count, len(results))

        return results

    # end method definition

    def _evaluate_odata_service_response(
        self,
        service: SAPODataServiceModel,
        url: str,
        response: requests.Response,
        activation_transaction: str,
    ) -> SAPODataServiceStatusModel:
        """Interpret the response of a service document request (helper of check_odata_apis()).

        Args:
            service (SAPODataServiceModel):
                The checked service.
            url (str):
                The called URL.
            response (requests.Response):
                The response of the service document request.
            activation_transaction (str):
                The SAP transaction to activate the service (depends on the OData version).

        Returns:
            SAPODataServiceStatusModel:
                The status of the service.

        """

        status_code = response.status_code

        if response.ok:
            # OData V2: {"d": {"EntitySets": ["A", "B"]}}
            # OData V4: {"value": [{"name": "A", "url": "A"}, ...]}
            try:
                document = response.json()
            except ValueError:
                return SAPODataServiceStatusModel(
                    service=service,
                    url=url,
                    state=SAPODataServiceState.ERROR,
                    http_status=status_code,
                    message="Service document is not valid JSON (content type -> '{}')".format(
                        response.headers.get("content-type", ""),
                    ),
                    hint="The URL may not point to an SAP OData service, or a proxy / login page "
                    "intercepted the request. Check the base URL.",
                )
            if "d" in document:
                entity_sets = list(document["d"].get("EntitySets", []))
            else:
                entity_sets = [
                    entry.get("name", "")
                    for entry in document.get("value", [])
                    if entry.get("kind", "EntitySet") == "EntitySet"
                ]
            missing_entity_sets = [entity_set for entity_set in service.entity_sets if entity_set not in entity_sets]
            if missing_entity_sets:
                return SAPODataServiceStatusModel(
                    service=service,
                    url=url,
                    state=SAPODataServiceState.INCOMPLETE,
                    http_status=status_code,
                    message="Missing entity sets -> {}".format(", ".join(missing_entity_sets)),
                    available_entity_sets=entity_sets,
                    missing_entity_sets=missing_entity_sets,
                    hint="The service is active but does not expose the expected entity sets. Check the "
                    "S/4HANA release and the service version in {}.".format(activation_transaction),
                )
            return SAPODataServiceStatusModel(
                service=service,
                url=url,
                state=SAPODataServiceState.ACTIVE,
                http_status=status_code,
                available_entity_sets=entity_sets,
            )

        error = SAPODataErrorModel.from_response(response)
        error_text = "{} {} {}".format(error.code, error.message, error.raw_text[:2000]).lower()

        if status_code == HTTPStatus.UNAUTHORIZED:
            state = SAPODataServiceState.UNAUTHORIZED
            hint = "Check user name, password and client. The user may also be locked (transaction SU01)."
        elif "/iwfnd/med/170" in error_text or "no service found" in error_text:
            # SAP Gateway: "No service found for namespace '', name '...', version '0001'":
            state = SAPODataServiceState.NOT_ACTIVATED
            hint = "Activate the service '{}' in transaction {} (and assign a system alias).".format(
                service.name,
                activation_transaction,
            )
        elif "service cannot be reached" in error_text or "icf node" in error_text:
            state = SAPODataServiceState.ICF_INACTIVE
            hint = "Activate the ICF node '{}' in transaction SICF.".format(service.path)
        elif status_code == HTTPStatus.FORBIDDEN:
            state = SAPODataServiceState.FORBIDDEN
            hint = (
                "The user is not authorized for the service. Assign a role with authorization object "
                "S_SERVICE for '{}' (check with transaction SU53 or /IWFND/ERROR_LOG).".format(service.name)
            )
        elif status_code == HTTPStatus.NOT_FOUND:
            state = SAPODataServiceState.NOT_ACTIVATED
            hint = (
                "Service not found. Activate the service '{}' in transaction {} and check the ICF node in SICF.".format(
                    service.name,
                    activation_transaction,
                )
            )
        else:
            state = SAPODataServiceState.ERROR
            hint = "Check the SAP Gateway error log (transaction /IWFND/ERROR_LOG) and the system log (SM21)."

        return SAPODataServiceStatusModel(
            service=service,
            url=url,
            state=state,
            http_status=status_code,
            message=str(error),
            hint=hint,
        )

    # end method definition

    @staticmethod
    def _quote_key(value: str) -> str:
        """Escape a value for use in an OData key or filter string literal (single quotes are doubled).

        Args:
            value (str):
                The value, e.g. "O'Brien".

        Returns:
            str:
                The escaped value, e.g. "O''Brien".

        """

        return str(value).replace("'", "''")

    # end method definition

    def _call_odata_function(self, service: str, function: str, parameters: dict, label: str) -> dict | None:
        """Call a function import (action) of an OData V2 service.

        SAP implements actions in OData V2 services (e.g. "ReleaseOrder") as function
        imports that are called with POST and their parameters in the query string.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            function (str):
                The name of the function import, e.g. "ReleaseOrder".
            parameters (dict):
                The parameters of the function import (None values are omitted).
            label (str):
                Describes the call for log messages, e.g. "release production order -> '1000123'".

        Returns:
            dict | None:
                The result of the function import (OData V2 "d" unwrapped) or None in case of an error.

        """

        url = self.service_url(service) + "/" + function
        params = {name: odata_literal(value) for name, value in parameters.items() if value is not None}

        self.logger.info("Call SAP function -> '%s' to %s...", function, label)
        response = self.do_request(
            url=url,
            method="POST",
            params=params,
            failure_message="Failed to {}".format(label),
            success_message="Successfully completed: {}.".format(label),
        )
        if response is None:
            return None

        return response.get("d", response)

    # end method definition

    def _call_odata_bound_action(
        self,
        service: str,
        entity_path: str,
        action: str,
        namespace: str,
        parameters: dict | None,
        label: str,
    ) -> dict | None:
        """Call a bound action of an OData V4 entity.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            entity_path (str):
                The path of the entity relative to the service root, e.g. "PlannedOrderHeader('1')".
            action (str):
                The name of the action, e.g. "SchedulePlannedOrder".
            namespace (str):
                The namespace of the action (the schema namespace of the service).
            parameters (dict | None):
                The action parameters (sent as JSON body).
            label (str):
                Describes the call for log messages, e.g. "schedule planned order -> '1'".

        Returns:
            dict | None:
                The result of the action (empty dict if there is none) or None in case of an error.

        """

        url = "{}/{}/{}.{}".format(self.service_url(service), entity_path, namespace, action)

        self.logger.info("Call SAP action -> '%s' to %s...", action, label)

        return self.do_request(
            url=url,
            method="POST",
            headers=ODATA_V4_IEEE754_HEADERS,
            json_data=parameters or {},
            failure_message="Failed to {}".format(label),
            success_message="Successfully completed: {}.".format(label),
        )

    # end method definition

    def _create_odata_entity(
        self,
        service: str,
        entity_set: str,
        model: type[SAPODataCreateModel],
        data: SAPODataCreateModel | dict,
        key_fields: list[str],
        label: str,
    ) -> dict | None:
        """Create an OData entity (deep insert / deep create) from a create model.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            entity_set (str):
                The entity set to create the entity in, e.g. "A_ProductionOrder_2".
            model (type[SAPODataCreateModel]):
                The create model used to validate dictionaries.
            data (SAPODataCreateModel | dict):
                The data of the new entity.
            key_fields (list[str]):
                The OData key fields that must be filled in the response (SAP may answer
                with success without creating the entity - then the keys are empty).
            label (str):
                The name of the entity for log messages, e.g. "production order".

        Returns:
            dict | None:
                The created entity as returned by SAP or None in case of an error.

        """

        if isinstance(data, dict):
            try:
                data = model.model_validate(data)
            except ValidationError as validation_error:
                self.log_error("Invalid %s data; error -> %s", label, str(validation_error))
                return None

        payload = data.to_odata()
        is_odata_v4 = SAP_ODATA_SERVICES[service].odata_version == 4
        self.logger.info("Create SAP %s...", label)
        self.logger.debug("SAP %s payload -> %s", label, str(payload))

        response = self.do_request(
            url=self.service_url(service) + "/" + entity_set,
            method="POST",
            headers=ODATA_V4_IEEE754_HEADERS if is_odata_v4 else None,
            json_data=payload,
            failure_message="Failed to create SAP {}".format(label),
        )
        if not response:
            return None

        created = response if is_odata_v4 else response.get("d", response)
        keys = {field: created.get(field) for field in key_fields}
        if not all(keys.values()):
            self.log_error("SAP did not create the %s (no key returned)!", label)
            self.logger.debug("Response -> %s", str(created))
            return None

        self.logger.info("Successfully created SAP %s -> %s.", label, ", ".join(str(value) for value in keys.values()))

        return created

    # end method definition

    def _get_odata_entity[T: BaseModel](
        self,
        service: str,
        entity_path: str,
        model: type[T],
        params: dict | None,
        label: str,
    ) -> T | None:
        """Read a single OData entity.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            entity_path (str):
                The path of the entity relative to the service root, e.g. "A_ProductionOrder_2('1000123')".
            model (type[T]):
                The response model the entity is validated into.
            params (dict | None):
                OData query options, e.g. {"$expand": "to_ProductionOrderOperation"}.
            label (str):
                The name of the entity for log messages, e.g. "production order -> '1000123'".

        Returns:
            T | None:
                The entity or None if it does not exist or in case of an error.

        """

        is_odata_v4 = SAP_ODATA_SERVICES[service].odata_version == 4
        response = self.do_request(
            url=self.service_url(service) + "/" + entity_path,
            params=params,
            headers=ODATA_V4_IEEE754_HEADERS if is_odata_v4 else None,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP {}".format(label),
        )
        if response is None:
            return None

        try:
            return model.model_validate(response if is_odata_v4 else response.get("d", {}))
        except ValidationError as validation_error:
            self.log_error("Cannot interpret SAP %s; error -> %s", label, str(validation_error))
            return None

    # end method definition

    def _iter_odata_collection[T: BaseModel](
        self,
        service: str,
        entity_set: str,
        model: type[T],
        query: SAPODataQueryModel,
        label: str,
    ) -> SAPODataIterator[T]:
        """Return an iterator that reads the entities of an OData collection page by page.

        Paging combines both mechanisms SAP uses:
        * Client-driven paging: each page is requested with $top (page size) and $skip.
          A page with fewer entities than requested is the last one.
        * Server-driven paging: if SAP limits the page size itself, it returns a link
          to the next page ("__next" in OData V2, "@odata.nextLink" in OData V4), which
          is followed until the requested page is complete.

        Pages should be read in a stable order (the query models always sort), as
        $skip refers to positions in the result. Documents that are created or deleted
        while iterating can shift these positions (an entity may be returned twice or
        be skipped).

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES, e.g. "API_MAINTENANCEORDER".
            entity_set (str):
                The entity set to read, e.g. "MaintenanceOrder".
            model (type[T]):
                The response model the entities are validated into.
            query (SAPODataQueryModel):
                The search criteria: filter, sort order, expanded child entities, the maximum
                number of entities (limit) and the page size.
            label (str):
                The (plural) name of the entities for log messages, e.g. "maintenance orders".

        Returns:
            SAPODataIterator[T]:
                The iterator over the entities (see SAPODataIterator.failed for errors).

        """

        odata_service = SAP_ODATA_SERVICES[service]
        is_odata_v4 = odata_service.odata_version == 4
        headers = ODATA_V4_IEEE754_HEADERS if is_odata_v4 else None
        collection_url = self.service_url(odata_service) + "/" + entity_set
        params = query.to_odata(odata_version=odata_service.odata_version)
        top, page_size = query.limit, query.page_size

        self.logger.info("Get SAP %s (query options -> %s, limit -> %s)...", label, str(params), str(top))

        def read_entities() -> Iterator[T]:
            count = 0  # entities returned so far
            skip = 0  # $skip of the current page
            window_size = 0  # entities requested for the current page ($top)
            window_count = 0  # entities read for the current page (incl. server-driven sub-pages)
            next_link = ""
            try:
                while True:
                    if next_link:
                        url, request_params = next_link, None
                    else:
                        window_size = page_size if top is None else min(page_size, top - count)
                        window_count = 0
                        url = collection_url
                        request_params = {**params, "$top": str(window_size)}
                        if skip:
                            request_params["$skip"] = str(skip)

                    response = self.do_request(
                        url=url,
                        params=request_params,
                        headers=headers,
                        failure_message="Failed to get SAP {}".format(label),
                    )
                    if response is None:
                        raise _ODataReadError

                    if is_odata_v4:
                        entities, link = response.get("value", []), response.get("@odata.nextLink", "")
                    else:
                        data = response.get("d", {})
                        entities, link = data.get("results", []), data.get("__next", "")

                    for entity in entities:
                        try:
                            item = model.model_validate(entity)
                        except ValidationError as validation_error:
                            self.log_error("Cannot interpret SAP %s; error -> %s", label, str(validation_error))
                            raise _ODataReadError from validation_error
                        yield item
                        count += 1
                        if top is not None and count >= top:
                            return

                    window_count += len(entities)
                    # The next link may be relative and already contains all query options:
                    next_link = urllib.parse.urljoin(url, link) if link else ""
                    if next_link:
                        continue
                    if window_count < window_size:
                        return  # last page
                    skip += window_count
            finally:
                self.logger.debug("Read %d SAP %s.", count, label)

        return SAPODataIterator(read_entities())

    # end method definition

    def _get_odata_etag(self, url: str, headers: dict, label: str) -> tuple[bool, str | None]:
        """Get the ETag of an OData entity (needed for the If-Match header of updates and deletes).

        Args:
            url (str):
                The URL of the entity.
            headers (dict):
                The request headers (e.g. for OData V4).
            label (str):
                The name of the entity for log messages, e.g. "sales order -> '413'".

        Returns:
            tuple[bool, str | None]:
                (True, ETag) if the entity exists - the ETag is None if the entity has
                none - or (False, None) if the entity does not exist or in case of an error.

        """

        response = self.do_request(
            url=url,
            headers=headers,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP {}".format(label),
            parse_request_response=False,
        )
        if response is None:
            return False, None

        etag = response.headers.get("ETag")
        if not etag:
            body = self.parse_request_response(response_object=response, show_error=False) or {}
            # OData V2: d.__metadata.etag, OData V4: @odata.etag:
            etag = (body.get("d", {}).get("__metadata", {}) or {}).get("etag") or body.get("@odata.etag")

        return True, etag

    # end method definition

    def _update_odata_entity(
        self,
        service: str,
        entity_path: str,
        model: type[SAPODataCreateModel],
        changes: dict,
        label: str,
    ) -> bool:
        """Update (PATCH) individual fields of an OData entity.

        The changed values are validated with the field definitions of the create
        model (see SAPODataCreateModel.to_odata_update()). The current ETag of the
        entity is sent in the If-Match header (optimistic locking) - SAP rejects the
        update if the entity has been changed in the meantime.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            entity_path (str):
                The path of the entity relative to the service root, e.g. "A_SalesOrder('413')".
            model (type[SAPODataCreateModel]):
                The create model whose field definitions are used for the changes.
            changes (dict):
                The fields to change (snake case attribute names or OData property names).
            label (str):
                The name of the entity for log messages, e.g. "sales order -> '413'".

        Returns:
            bool:
                True if the entity has been updated, False in case of an error.

        """

        try:
            payload = model.to_odata_update(changes)
        except ValueError as value_error:
            self.log_error("Invalid changes for SAP %s; error -> %s", label, str(value_error))
            return False
        if not payload:
            self.logger.warning("No changes given for SAP %s - nothing to update.", label)
            return True

        url = self.service_url(service) + "/" + entity_path
        headers = dict(ODATA_V4_IEEE754_HEADERS) if SAP_ODATA_SERVICES[service].odata_version == 4 else {}
        exists, etag = self._get_odata_etag(url=url, headers=headers, label=label)
        if not exists:
            return False
        if not etag:
            # SAP requires an If-Match header - "*" matches any version (no optimistic locking):
            self.logger.warning(
                "SAP %s has no ETag - changing it without optimistic locking (concurrent changes may be overwritten)!",
                label,
            )
        headers["If-Match"] = etag or "*"

        self.logger.info("Update SAP %s with -> %s ...", label, str(payload))
        response = self.do_request(
            url=url,
            method="PATCH",
            headers=headers,
            json_data=payload,
            failure_message="Failed to update SAP {}".format(label),
            success_message="Successfully updated SAP {}.".format(label),
        )

        return response is not None

    # end method definition

    def _delete_odata_entity(self, service: str, entity_path: str, label: str) -> bool:
        """Delete an OData entity.

        The current ETag of the entity is sent in the If-Match header (optimistic locking).

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            entity_path (str):
                The path of the entity relative to the service root, e.g. "A_SalesOrder('413')".
            label (str):
                The name of the entity for log messages, e.g. "sales order -> '413'".

        Returns:
            bool:
                True if the entity has been deleted, False in case of an error.

        """

        url = self.service_url(service) + "/" + entity_path
        headers = dict(ODATA_V4_IEEE754_HEADERS) if SAP_ODATA_SERVICES[service].odata_version == 4 else {}
        exists, etag = self._get_odata_etag(url=url, headers=headers, label=label)
        if not exists:
            return False
        if not etag:
            # SAP requires an If-Match header - "*" matches any version (no optimistic locking):
            self.logger.warning(
                "SAP %s has no ETag - changing it without optimistic locking (concurrent changes may be overwritten)!",
                label,
            )
        headers["If-Match"] = etag or "*"

        self.logger.info("Delete SAP %s...", label)
        response = self.do_request(
            url=url,
            method="DELETE",
            headers=headers,
            failure_message="Failed to delete SAP {}".format(label),
            success_message="Successfully deleted SAP {}.".format(label),
        )

        return response is not None

    # end method definition

    def create_maintenance_order(self, order: SAPMaintenanceOrderModel | dict) -> dict | None:
        """Create an SAP Plant Maintenance order (including its operations).

        Uses the OData V2 API API_MAINTENANCEORDER with a deep insert, so the order
        header and all operations are created (and committed) in one request.

        Args:
            order (SAPMaintenanceOrderModel | dict):
                The order data. A dictionary is validated against the SAPMaintenanceOrderModel
                model and can use either the snake case attribute names or the OData
                property names (e.g. "order_type" or "MaintenanceOrderType").

        Returns:
            dict | None:
                The created maintenance order as returned by SAP (including the
                order number in "MaintenanceOrder") or None in case of an error.

        Example:
            >>> sap.create_maintenance_order(
            ...     {
            ...         "order_type": "YA01",
            ...         "description": "Replace pump seal",
            ...         "planning_plant": "1010",
            ...         "main_work_center": "RES-0100",
            ...         "main_work_center_plant": "1010",
            ...         "equipment": "210100001",
            ...         "operations": [{"operation": "10", "description": "Replace seal", "control_key": "YBM1"}],
            ...     }
            ... )

        """

        return self._create_odata_entity(
            service="API_MAINTENANCEORDER",
            entity_set="MaintenanceOrder",
            model=SAPMaintenanceOrderModel,
            data=order,
            key_fields=["MaintenanceOrder"],
            label="maintenance order",
        )

    # end method definition

    def iter_maintenance_orders(
        self, query: SAPMaintenanceOrderQueryModel | None = None
    ) -> SAPODataIterator[SAPMaintenanceOrderResponseModel]:
        """Iterate over SAP maintenance orders - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPMaintenanceOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all maintenance orders).

        Returns:
            SAPODataIterator[SAPMaintenanceOrderResponseModel]:
                The iterator over the maintenance orders.

        """

        return self._iter_odata_collection(
            service="API_MAINTENANCEORDER",
            entity_set="MaintenanceOrder",
            model=SAPMaintenanceOrderResponseModel,
            query=query or SAPMaintenanceOrderQueryModel(),
            label="maintenance orders",
        )

    # end method definition

    def get_maintenance_orders(
        self, query: SAPMaintenanceOrderQueryModel | None = None
    ) -> list[SAPMaintenanceOrderResponseModel] | None:
        """Get SAP maintenance orders as a list.

        All matching maintenance orders are read (page by page, see iter_maintenance_orders()) and returned at once.
        For very large result sets prefer iter_maintenance_orders().

        Args:
            query (SAPMaintenanceOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all maintenance orders).

        Returns:
            list[SAPMaintenanceOrderResponseModel] | None:
                The maintenance orders (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_maintenance_orders(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP maintenance orders.", len(results))

        return results

    # end method definition

    def get_maintenance_order(
        self,
        order_id: str,
        expand_operations: bool = True,
    ) -> SAPMaintenanceOrderResponseModel | None:
        """Get a single SAP Plant Maintenance order by its order number.

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            expand_operations (bool, optional):
                Whether to read the operations of the order as well. Defaults to True.

        Returns:
            SAPMaintenanceOrderResponseModel | None:
                The maintenance order or None if it does not exist or in case of an error.

        """

        # Single quotes in OData key values are escaped by doubling them:
        url = self.service_url("API_MAINTENANCEORDER") + "/MaintenanceOrder('{}')".format(order_id.replace("'", "''"))
        params = {"$expand": "to_MaintenanceOrderOperation"} if expand_operations else None

        response = self.do_request(
            url=url,
            params=params,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP maintenance order -> '{}'".format(order_id),
        )
        if response is None:
            return None

        try:
            return SAPMaintenanceOrderResponseModel.model_validate(response.get("d", {}))
        except ValidationError as validation_error:
            self.log_error(
                "Cannot interpret SAP maintenance order -> '%s'; error -> %s",
                order_id,
                str(validation_error),
            )
            return None

    # end method definition

    def update_maintenance_order(self, order_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP maintenance order.

        The changes are validated with the field definitions of SAPMaintenanceOrderModel (e.g. upper
        case codes, lengths, date formats). Items cannot be changed with this method.

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            changes (dict):
                The fields to change - snake case attribute names of SAPMaintenanceOrderModel or OData
                property names, e.g. {"description": "Replace pump seal", "priority": "1"}.

        Returns:
            bool:
                True if the maintenance order has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_MAINTENANCEORDER",
            entity_path="MaintenanceOrder('{}')".format(order_id.replace("'", "''")),
            model=SAPMaintenanceOrderModel,
            changes=changes,
            label="maintenance order -> '{}'".format(order_id),
        )

    # end method definition

    def change_maintenance_order_status(
        self,
        order_id: str,
        action: SAPMaintenanceOrderAction,
        parameters: dict | None = None,
    ) -> bool:
        """Change the status of an SAP maintenance order (e.g. release, technically complete or close).

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            action (SAPMaintenanceOrderAction):
                The status action, e.g. SAPMaintenanceOrderAction.RELEASE.
            parameters (dict | None, optional):
                Additional (optional) parameters of the action with their OData names. Defaults to None.

        Returns:
            bool:
                True if the status has been changed, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_MAINTENANCEORDER",
            function=str(action),
            parameters={"MaintenanceOrder": order_id, **(parameters or {})},
            label="{} maintenance order -> '{}'".format(action.name.lower().replace("_", " "), order_id),
        )

        return result is not None

    # end method definition

    def create_purchase_order(self, order: SAPPurchaseOrderModel | dict) -> dict | None:
        """Create an SAP purchase order including its items, schedule lines and account assignments.

        Uses the OData V4 API API_PURCHASEORDER_2 with a deep create, so the whole
        purchase order is created (and committed) in one request.

        Args:
            order (SAPPurchaseOrderModel | dict):
                The purchase order data. A dictionary is validated against the
                SAPPurchaseOrderModel and can use either the snake case attribute
                names or the OData property names (e.g. "supplier" or "Supplier").

        Returns:
            dict | None:
                The created purchase order as returned by SAP (including the purchase
                order number in "PurchaseOrder") or None in case of an error.

        Example:
            >>> sap.create_purchase_order(
            ...     {
            ...         "company_code": "3000",
            ...         "purchasing_organization": "3000",
            ...         "purchasing_group": "001",
            ...         "supplier": "30050",
            ...         "items": [
            ...             {
            ...                 "material": "R-9010",
            ...                 "plant": "3000",
            ...                 "quantity": "20",
            ...                 "net_price": "32.00",
            ...                 "account_assignment_category": "K",
            ...                 "schedule_lines": [{"delivery_date": "2026-11-01"}],
            ...                 "account_assignments": [{"cost_center": "4130", "gl_account": "400000"}],
            ...             },
            ...         ],
            ...     }
            ... )

        """

        return self._create_odata_entity(
            service="API_PURCHASEORDER_2",
            entity_set="PurchaseOrder",
            model=SAPPurchaseOrderModel,
            data=order,
            key_fields=["PurchaseOrder"],
            label="purchase order",
        )

    # end method definition

    def iter_purchase_orders(
        self, query: SAPPurchaseOrderQueryModel | None = None
    ) -> SAPODataIterator[SAPPurchaseOrderResponseModel]:
        """Iterate over SAP purchase orders - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPPurchaseOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all purchase orders).

        Returns:
            SAPODataIterator[SAPPurchaseOrderResponseModel]:
                The iterator over the purchase orders.

        """

        return self._iter_odata_collection(
            service="API_PURCHASEORDER_2",
            entity_set="PurchaseOrder",
            model=SAPPurchaseOrderResponseModel,
            query=query or SAPPurchaseOrderQueryModel(),
            label="purchase orders",
        )

    # end method definition

    def get_purchase_orders(
        self, query: SAPPurchaseOrderQueryModel | None = None
    ) -> list[SAPPurchaseOrderResponseModel] | None:
        """Get SAP purchase orders as a list.

        All matching purchase orders are read (page by page, see iter_purchase_orders()) and returned at once.
        For very large result sets prefer iter_purchase_orders().

        Args:
            query (SAPPurchaseOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all purchase orders).

        Returns:
            list[SAPPurchaseOrderResponseModel] | None:
                The purchase orders (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_purchase_orders(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP purchase orders.", len(results))

        return results

    # end method definition

    def get_purchase_order(
        self,
        order_id: str,
        expand_items: bool = True,
    ) -> SAPPurchaseOrderResponseModel | None:
        """Get a single SAP purchase order by its number.

        Args:
            order_id (str):
                The purchase order number, e.g. "4500001539".
            expand_items (bool, optional):
                Whether to read the items (with schedule lines and account assignments)
                as well. Defaults to True.

        Returns:
            SAPPurchaseOrderResponseModel | None:
                The purchase order or None if it does not exist or in case of an error.

        """

        # Single quotes in OData key values are escaped by doubling them:
        url = self.service_url("API_PURCHASEORDER_2") + "/PurchaseOrder('{}')".format(order_id.replace("'", "''"))
        params = {"$expand": PURCHASE_ORDER_EXPAND_ITEMS} if expand_items else None

        response = self.do_request(
            url=url,
            params=params,
            headers=ODATA_V4_IEEE754_HEADERS,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP purchase order -> '{}'".format(order_id),
        )
        if response is None:
            return None

        try:
            return SAPPurchaseOrderResponseModel.model_validate(response)
        except ValidationError as validation_error:
            self.log_error(
                "Cannot interpret SAP purchase order -> '%s'; error -> %s",
                order_id,
                str(validation_error),
            )
            return None

    # end method definition

    def update_purchase_order(self, order_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP purchase order.

        The changes are validated with the field definitions of SAPPurchaseOrderModel (e.g. upper
        case codes, lengths, date formats). Items cannot be changed with this method.

        Args:
            order_id (str):
                The purchase order number, e.g. "4500001539".
            changes (dict):
                The fields to change - snake case attribute names of SAPPurchaseOrderModel or OData
                property names, e.g. {"your_reference": "PO-4711", "payment_terms": "0001"}.

        Returns:
            bool:
                True if the purchase order has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_PURCHASEORDER_2",
            entity_path="PurchaseOrder('{}')".format(order_id.replace("'", "''")),
            model=SAPPurchaseOrderModel,
            changes=changes,
            label="purchase order -> '{}'".format(order_id),
        )

    # end method definition

    def delete_purchase_order(self, order_id: str) -> bool:
        """Delete an SAP purchase order.

        Args:
            order_id (str):
                The purchase order number, e.g. "4500001539".

        Returns:
            bool:
                True if the purchase order has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_PURCHASEORDER_2",
            entity_path="PurchaseOrder('{}')".format(order_id.replace("'", "''")),
            label="purchase order -> '{}'".format(order_id),
        )

    # end method definition

    def create_maintenance_notification(self, notification: SAPMaintenanceNotificationModel | dict) -> dict | None:
        """Create an SAP maintenance notification (including its items).

        Uses the OData V2 API API_MAINTNOTIFICATION with a deep insert, so the
        notification and all items are created (and committed) in one request.

        Args:
            notification (SAPMaintenanceNotificationModel | dict):
                The notification data. A dictionary is validated against the
                SAPMaintenanceNotificationModel and can use either the snake case
                attribute names or the OData property names (e.g. "text" or "NotificationText").

        Returns:
            dict | None:
                The created notification as returned by SAP (including the notification
                number in "MaintenanceNotification") or None in case of an error.

        Example:
            >>> sap.create_maintenance_notification(
            ...     {
            ...         "notification_type": "M2",
            ...         "text": "Pump is leaking",
            ...         "priority": "2",
            ...         "technical_object": "P-3000-N001",
            ...         "technical_object_type": "EAMS_EQUI",
            ...         "breakdown": True,
            ...     }
            ... )

        """

        return self._create_odata_entity(
            service="API_MAINTNOTIFICATION",
            entity_set="MaintenanceNotification",
            model=SAPMaintenanceNotificationModel,
            data=notification,
            key_fields=["MaintenanceNotification"],
            label="maintenance notification",
        )

    # end method definition

    def iter_maintenance_notifications(
        self, query: SAPMaintenanceNotificationQueryModel | None = None
    ) -> SAPODataIterator[SAPMaintenanceNotificationResponseModel]:
        """Iterate over SAP maintenance notifications - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPMaintenanceNotificationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all maintenance notifications).

        Returns:
            SAPODataIterator[SAPMaintenanceNotificationResponseModel]:
                The iterator over the maintenance notifications.

        """

        return self._iter_odata_collection(
            service="API_MAINTNOTIFICATION",
            entity_set="MaintenanceNotification",
            model=SAPMaintenanceNotificationResponseModel,
            query=query or SAPMaintenanceNotificationQueryModel(),
            label="maintenance notifications",
        )

    # end method definition

    def get_maintenance_notifications(
        self, query: SAPMaintenanceNotificationQueryModel | None = None
    ) -> list[SAPMaintenanceNotificationResponseModel] | None:
        """Get SAP maintenance notifications as a list.

        All matching maintenance notifications are read (page by page, see iter_maintenance_notifications()) and returned at once.
        For very large result sets prefer iter_maintenance_notifications().

        Args:
            query (SAPMaintenanceNotificationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all maintenance notifications).

        Returns:
            list[SAPMaintenanceNotificationResponseModel] | None:
                The maintenance notifications (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_maintenance_notifications(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP maintenance notifications.", len(results))

        return results

    # end method definition

    def get_maintenance_notification(
        self,
        notification_id: str,
        expand_items: bool = True,
    ) -> SAPMaintenanceNotificationResponseModel | None:
        """Get a single SAP maintenance notification by its number.

        Args:
            notification_id (str):
                The notification number, e.g. "10000210" (leading zeros are optional).
            expand_items (bool, optional):
                Whether to read the items of the notification as well. Defaults to True.

        Returns:
            SAPMaintenanceNotificationResponseModel | None:
                The notification or None if it does not exist or in case of an error.

        """

        # Single quotes in OData key values are escaped by doubling them:
        url = self.service_url("API_MAINTNOTIFICATION") + "/MaintenanceNotification('{}')".format(
            notification_id.replace("'", "''"),
        )
        params = {"$expand": "to_Item"} if expand_items else None

        response = self.do_request(
            url=url,
            params=params,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP maintenance notification -> '{}'".format(notification_id),
        )
        if response is None:
            return None

        try:
            return SAPMaintenanceNotificationResponseModel.model_validate(response.get("d", {}))
        except ValidationError as validation_error:
            self.log_error(
                "Cannot interpret SAP maintenance notification -> '%s'; error -> %s",
                notification_id,
                str(validation_error),
            )
            return None

    # end method definition

    def update_maintenance_notification(self, notification_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP maintenance notification.

        The changes are validated with the field definitions of SAPMaintenanceNotificationModel (e.g. upper
        case codes, lengths, date formats). Items cannot be changed with this method.

        Args:
            notification_id (str):
                The maintenance notification number, e.g. "10000210".
            changes (dict):
                The fields to change - snake case attribute names of SAPMaintenanceNotificationModel or OData
                property names, e.g. {"priority": "1", "breakdown": True}.

        Returns:
            bool:
                True if the maintenance notification has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_MAINTNOTIFICATION",
            entity_path="MaintenanceNotification('{}')".format(notification_id.replace("'", "''")),
            model=SAPMaintenanceNotificationModel,
            changes=changes,
            label="maintenance notification -> '{}'".format(notification_id),
        )

    # end method definition

    def change_maintenance_notification_status(
        self,
        notification_id: str,
        action: SAPMaintenanceNotificationAction,
        parameters: dict | None = None,
    ) -> bool:
        """Change the status of an SAP maintenance notification (e.g. complete or set in process).

        Args:
            notification_id (str):
                The maintenance notification number, e.g. "10000210".
            action (SAPMaintenanceNotificationAction):
                The status action, e.g. SAPMaintenanceNotificationAction.COMPLETE.
            parameters (dict | None, optional):
                Additional (optional) parameters of the action with their OData names. Defaults to None.

        Returns:
            bool:
                True if the status has been changed, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_MAINTNOTIFICATION",
            function=str(action),
            parameters={"MaintenanceNotification": notification_id, **(parameters or {})},
            label="{} maintenance notification -> '{}'".format(action.name.lower().replace("_", " "), notification_id),
        )

        return result is not None

    # end method definition

    def create_sales_order(self, order: SAPSalesOrderModel | dict) -> dict | None:
        """Create an SAP sales order (including its items).

        Uses the OData V2 API API_SALES_ORDER_SRV with a deep insert, so the sales order and all
        items are created (and committed) in one request.

        Args:
            order (SAPSalesOrderModel | dict):
                The sales order data. A dictionary is validated against the SAPSalesOrderModel
                and can use either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created sales order as returned by SAP (including the number in
                "SalesOrder") or None in case of an error.

        Example:
            >>> sap.create_sales_order(
            ... {
            ...     "order_type": "YT",
            ...     "sales_organization": "3000",
            ...     "distribution_channel": "10",
            ...     "division": "00",
            ...     "sold_to_party": "52001",
            ...     "customer_reference": "PO-4711",
            ...     "items": [{"material": "P-100", "quantity": "10"}],
            ... }
            ... )

        """

        return self._create_odata_entity(
            service="API_SALES_ORDER_SRV",
            entity_set="A_SalesOrder",
            model=SAPSalesOrderModel,
            data=order,
            key_fields=["SalesOrder"],
            label="sales order",
        )

    # end method definition

    def iter_sales_orders(
        self, query: SAPSalesOrderQueryModel | None = None
    ) -> SAPODataIterator[SAPSalesOrderResponseModel]:
        """Iterate over SAP sales orders - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPSalesOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all sales orders).

        Returns:
            SAPODataIterator[SAPSalesOrderResponseModel]:
                The iterator over the sales orders.

        """

        return self._iter_odata_collection(
            service="API_SALES_ORDER_SRV",
            entity_set="A_SalesOrder",
            model=SAPSalesOrderResponseModel,
            query=query or SAPSalesOrderQueryModel(),
            label="sales orders",
        )

    # end method definition

    def get_sales_orders(self, query: SAPSalesOrderQueryModel | None = None) -> list[SAPSalesOrderResponseModel] | None:
        """Get SAP sales orders as a list.

        All matching sales orders are read (page by page, see iter_sales_orders()) and returned at once.
        For very large result sets prefer iter_sales_orders().

        Args:
            query (SAPSalesOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all sales orders).

        Returns:
            list[SAPSalesOrderResponseModel] | None:
                The sales orders (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_sales_orders(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP sales orders.", len(results))

        return results

    # end method definition

    def get_sales_order(
        self,
        order_id: str,
        expand_items: bool = True,
    ) -> SAPSalesOrderResponseModel | None:
        """Get a single SAP sales order by its number.

        Args:
            order_id (str):
                The sales order number, e.g. "413".
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPSalesOrderResponseModel | None:
                The sales order or None if it does not exist or in case of an error.

        """

        # Single quotes in OData key values are escaped by doubling them:
        url = self.service_url("API_SALES_ORDER_SRV") + "/A_SalesOrder('{}')".format(order_id.replace("'", "''"))
        params = {"$expand": "to_Item"} if expand_items else None

        response = self.do_request(
            url=url,
            params=params,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP sales order -> '{}'".format(order_id),
        )
        if response is None:
            return None

        try:
            return SAPSalesOrderResponseModel.model_validate(response.get("d", {}))
        except ValidationError as validation_error:
            self.log_error("Cannot interpret SAP sales order -> '%s'; error -> %s", order_id, str(validation_error))
            return None

    # end method definition

    def update_sales_order(self, order_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP sales order.

        The changes are validated with the field definitions of SAPSalesOrderModel (e.g. upper
        case codes, lengths, date formats). Items cannot be changed with this method.

        Args:
            order_id (str):
                The sales order number, e.g. "413".
            changes (dict):
                The fields to change - snake case attribute names of SAPSalesOrderModel or OData
                property names, e.g. {"requested_delivery_date": "2026-12-01"}.

        Returns:
            bool:
                True if the sales order has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_SALES_ORDER_SRV",
            entity_path="A_SalesOrder('{}')".format(order_id.replace("'", "''")),
            model=SAPSalesOrderModel,
            changes=changes,
            label="sales order -> '{}'".format(order_id),
        )

    # end method definition

    def delete_sales_order(self, order_id: str) -> bool:
        """Delete an SAP sales order.

        Args:
            order_id (str):
                The sales order number, e.g. "413".

        Returns:
            bool:
                True if the sales order has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_SALES_ORDER_SRV",
            entity_path="A_SalesOrder('{}')".format(order_id.replace("'", "''")),
            label="sales order -> '{}'".format(order_id),
        )

    # end method definition

    def create_sales_contract(self, contract: SAPSalesContractModel | dict) -> dict | None:
        """Create an SAP sales contract (including its items).

        Uses the OData V2 API API_SALES_CONTRACT_SRV with a deep insert, so the sales contract and all
        items are created (and committed) in one request.

        Args:
            contract (SAPSalesContractModel | dict):
                The sales contract data. A dictionary is validated against the SAPSalesContractModel
                and can use either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created sales contract as returned by SAP (including the number in
                "SalesContract") or None in case of an error.

        Example:
            >>> sap.create_sales_contract(
            ... {
            ...     "contract_type": "YC",
            ...     "sales_organization": "1000",
            ...     "distribution_channel": "10",
            ...     "division": "00",
            ...     "sold_to_party": "50031",
            ...     "validity_start_date": "2026-11-01",
            ...     "validity_end_date": "2027-10-31",
            ... }
            ... )

        """

        return self._create_odata_entity(
            service="API_SALES_CONTRACT_SRV",
            entity_set="A_SalesContract",
            model=SAPSalesContractModel,
            data=contract,
            key_fields=["SalesContract"],
            label="sales contract",
        )

    # end method definition

    def iter_sales_contracts(
        self, query: SAPSalesContractQueryModel | None = None
    ) -> SAPODataIterator[SAPSalesContractResponseModel]:
        """Iterate over SAP sales contracts - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPSalesContractQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all sales contracts).

        Returns:
            SAPODataIterator[SAPSalesContractResponseModel]:
                The iterator over the sales contracts.

        """

        return self._iter_odata_collection(
            service="API_SALES_CONTRACT_SRV",
            entity_set="A_SalesContract",
            model=SAPSalesContractResponseModel,
            query=query or SAPSalesContractQueryModel(),
            label="sales contracts",
        )

    # end method definition

    def get_sales_contracts(
        self, query: SAPSalesContractQueryModel | None = None
    ) -> list[SAPSalesContractResponseModel] | None:
        """Get SAP sales contracts as a list.

        All matching sales contracts are read (page by page, see iter_sales_contracts()) and returned at once.
        For very large result sets prefer iter_sales_contracts().

        Args:
            query (SAPSalesContractQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all sales contracts).

        Returns:
            list[SAPSalesContractResponseModel] | None:
                The sales contracts (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_sales_contracts(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP sales contracts.", len(results))

        return results

    # end method definition

    def get_sales_contract(
        self,
        contract_id: str,
        expand_items: bool = True,
    ) -> SAPSalesContractResponseModel | None:
        """Get a single SAP sales contract by its number.

        Args:
            contract_id (str):
                The sales contract number, e.g. "40000040".
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPSalesContractResponseModel | None:
                The sales contract or None if it does not exist or in case of an error.

        """

        # Single quotes in OData key values are escaped by doubling them:
        url = self.service_url("API_SALES_CONTRACT_SRV") + "/A_SalesContract('{}')".format(
            contract_id.replace("'", "''")
        )
        params = {"$expand": "to_Item"} if expand_items else None

        response = self.do_request(
            url=url,
            params=params,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP sales contract -> '{}'".format(contract_id),
        )
        if response is None:
            return None

        try:
            return SAPSalesContractResponseModel.model_validate(response.get("d", {}))
        except ValidationError as validation_error:
            self.log_error(
                "Cannot interpret SAP sales contract -> '%s'; error -> %s", contract_id, str(validation_error)
            )
            return None

    # end method definition

    def update_sales_contract(self, contract_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP sales contract.

        The changes are validated with the field definitions of SAPSalesContractModel (e.g. upper
        case codes, lengths, date formats). Items cannot be changed with this method.

        Args:
            contract_id (str):
                The sales contract number, e.g. "40000040".
            changes (dict):
                The fields to change - snake case attribute names of SAPSalesContractModel or OData
                property names, e.g. {"validity_end_date": "2027-12-31"}.

        Returns:
            bool:
                True if the sales contract has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_SALES_CONTRACT_SRV",
            entity_path="A_SalesContract('{}')".format(contract_id.replace("'", "''")),
            model=SAPSalesContractModel,
            changes=changes,
            label="sales contract -> '{}'".format(contract_id),
        )

    # end method definition

    def delete_sales_contract(self, contract_id: str) -> bool:
        """Delete an SAP sales contract.

        Args:
            contract_id (str):
                The sales contract number, e.g. "40000040".

        Returns:
            bool:
                True if the sales contract has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_SALES_CONTRACT_SRV",
            entity_path="A_SalesContract('{}')".format(contract_id.replace("'", "''")),
            label="sales contract -> '{}'".format(contract_id),
        )

    # end method definition

    def create_purchase_contract(self, contract: SAPPurchaseContractModel | dict) -> dict | None:
        """Create an SAP purchase contract (including its items).

        Uses the OData V2 API API_PURCHASECONTRACT_PROCESS_SRV with a deep insert, so the purchase contract and all
        items are created (and committed) in one request.

        Args:
            contract (SAPPurchaseContractModel | dict):
                The purchase contract data. A dictionary is validated against the SAPPurchaseContractModel
                and can use either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created purchase contract as returned by SAP (including the number in
                "PurchaseContract") or None in case of an error.

        Example:
            >>> sap.create_purchase_contract(
            ... {
            ...     "company_code": "3000",
            ...     "purchasing_organization": "3000",
            ...     "purchasing_group": "001",
            ...     "supplier": "30010",
            ...     "validity_start_date": "2026-11-01",
            ...     "validity_end_date": "2027-10-31",
            ...     "items": [{"material": "R-9000", "plant": "3000", "target_quantity": "100", "net_price": "950.00"}],
            ... }
            ... )

        """

        return self._create_odata_entity(
            service="API_PURCHASECONTRACT_PROCESS_SRV",
            entity_set="A_PurchaseContract",
            model=SAPPurchaseContractModel,
            data=contract,
            key_fields=["PurchaseContract"],
            label="purchase contract",
        )

    # end method definition

    def iter_purchase_contracts(
        self, query: SAPPurchaseContractQueryModel | None = None
    ) -> SAPODataIterator[SAPPurchaseContractResponseModel]:
        """Iterate over SAP purchase contracts - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPPurchaseContractQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all purchase contracts).

        Returns:
            SAPODataIterator[SAPPurchaseContractResponseModel]:
                The iterator over the purchase contracts.

        """

        return self._iter_odata_collection(
            service="API_PURCHASECONTRACT_PROCESS_SRV",
            entity_set="A_PurchaseContract",
            model=SAPPurchaseContractResponseModel,
            query=query or SAPPurchaseContractQueryModel(),
            label="purchase contracts",
        )

    # end method definition

    def get_purchase_contracts(
        self, query: SAPPurchaseContractQueryModel | None = None
    ) -> list[SAPPurchaseContractResponseModel] | None:
        """Get SAP purchase contracts as a list.

        All matching purchase contracts are read (page by page, see iter_purchase_contracts()) and returned at once.
        For very large result sets prefer iter_purchase_contracts().

        Args:
            query (SAPPurchaseContractQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all purchase contracts).

        Returns:
            list[SAPPurchaseContractResponseModel] | None:
                The purchase contracts (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_purchase_contracts(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP purchase contracts.", len(results))

        return results

    # end method definition

    def get_purchase_contract(
        self,
        contract_id: str,
        expand_items: bool = True,
    ) -> SAPPurchaseContractResponseModel | None:
        """Get a single SAP purchase contract by its number.

        Args:
            contract_id (str):
                The purchase contract number, e.g. "4600000070".
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPPurchaseContractResponseModel | None:
                The purchase contract or None if it does not exist or in case of an error.

        """

        # Single quotes in OData key values are escaped by doubling them:
        url = self.service_url("API_PURCHASECONTRACT_PROCESS_SRV") + "/A_PurchaseContract('{}')".format(
            contract_id.replace("'", "''")
        )
        params = {"$expand": "to_PurchaseContractItem"} if expand_items else None

        response = self.do_request(
            url=url,
            params=params,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP purchase contract -> '{}'".format(contract_id),
        )
        if response is None:
            return None

        try:
            return SAPPurchaseContractResponseModel.model_validate(response.get("d", {}))
        except ValidationError as validation_error:
            self.log_error(
                "Cannot interpret SAP purchase contract -> '%s'; error -> %s", contract_id, str(validation_error)
            )
            return None

    # end method definition

    def create_purchase_requisition(self, requisition: SAPPurchaseRequisitionModel | dict) -> dict | None:
        """Create an SAP purchase requisition including its items (and their account assignments).

        Uses the OData V4 API API_PURCHASEREQUISITION_2 with a deep create, so the whole purchase requisition
        is created (and committed) in one request.

        Args:
            requisition (SAPPurchaseRequisitionModel | dict):
                The purchase requisition data. A dictionary is validated against the SAPPurchaseRequisitionModel
                and can use either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created purchase requisition as returned by SAP (including the number in
                "PurchaseRequisition") or None in case of an error.

        Example:
            >>> sap.create_purchase_requisition(
            ... {
            ...     "description": "Notebook web cams",
            ...     "items": [
            ...         {
            ...             "material": "R-9010",
            ...             "quantity": "10",
            ...             "plant": "3000",
            ...             "purchasing_group": "003",
            ...             "delivery_date": "2026-11-01",
            ...         },
            ...     ],
            ... }
            ... )

        """

        return self._create_odata_entity(
            service="API_PURCHASEREQUISITION_2",
            entity_set="PurchaseReqn",
            model=SAPPurchaseRequisitionModel,
            data=requisition,
            key_fields=["PurchaseRequisition"],
            label="purchase requisition",
        )

    # end method definition

    def iter_purchase_requisitions(
        self, query: SAPPurchaseRequisitionQueryModel | None = None
    ) -> SAPODataIterator[SAPPurchaseRequisitionResponseModel]:
        """Iterate over SAP purchase requisitions - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPPurchaseRequisitionQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all purchase requisitions).

        Returns:
            SAPODataIterator[SAPPurchaseRequisitionResponseModel]:
                The iterator over the purchase requisitions.

        """

        return self._iter_odata_collection(
            service="API_PURCHASEREQUISITION_2",
            entity_set="PurchaseReqn",
            model=SAPPurchaseRequisitionResponseModel,
            query=query or SAPPurchaseRequisitionQueryModel(),
            label="purchase requisitions",
        )

    # end method definition

    def get_purchase_requisitions(
        self, query: SAPPurchaseRequisitionQueryModel | None = None
    ) -> list[SAPPurchaseRequisitionResponseModel] | None:
        """Get SAP purchase requisitions as a list.

        All matching purchase requisitions are read (page by page, see iter_purchase_requisitions()) and returned at once.
        For very large result sets prefer iter_purchase_requisitions().

        Args:
            query (SAPPurchaseRequisitionQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all purchase requisitions).

        Returns:
            list[SAPPurchaseRequisitionResponseModel] | None:
                The purchase requisitions (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_purchase_requisitions(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP purchase requisitions.", len(results))

        return results

    # end method definition

    def get_purchase_requisition(
        self,
        requisition_id: str,
        expand_items: bool = True,
    ) -> SAPPurchaseRequisitionResponseModel | None:
        """Get a single SAP purchase requisition by its number.

        Args:
            requisition_id (str):
                The purchase requisition number, e.g. "10000151".
            expand_items (bool, optional):
                Whether to read the items (with account assignments) as well. Defaults to True.

        Returns:
            SAPPurchaseRequisitionResponseModel | None:
                The purchase requisition or None if it does not exist or in case of an error.

        """

        # Single quotes in OData key values are escaped by doubling them:
        url = self.service_url("API_PURCHASEREQUISITION_2") + "/PurchaseReqn('{}')".format(
            requisition_id.replace("'", "''")
        )
        params = {"$expand": PURCHASE_REQUISITION_EXPAND_ITEMS} if expand_items else None

        response = self.do_request(
            url=url,
            params=params,
            headers=ODATA_V4_IEEE754_HEADERS,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP purchase requisition -> '{}'".format(requisition_id),
        )
        if response is None:
            return None

        try:
            return SAPPurchaseRequisitionResponseModel.model_validate(response)
        except ValidationError as validation_error:
            self.log_error(
                "Cannot interpret SAP purchase requisition -> '%s'; error -> %s", requisition_id, str(validation_error)
            )
            return None

    # end method definition

    def update_purchase_requisition(self, requisition_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP purchase requisition.

        The changes are validated with the field definitions of SAPPurchaseRequisitionModel (e.g. upper
        case codes, lengths, date formats). Items cannot be changed with this method.

        Args:
            requisition_id (str):
                The purchase requisition number, e.g. "10000151".
            changes (dict):
                The fields to change - snake case attribute names of SAPPurchaseRequisitionModel or OData
                property names, e.g. {"description": "Web cams for the training room"}.

        Returns:
            bool:
                True if the purchase requisition has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_PURCHASEREQUISITION_2",
            entity_path="PurchaseReqn('{}')".format(requisition_id.replace("'", "''")),
            model=SAPPurchaseRequisitionModel,
            changes=changes,
            label="purchase requisition -> '{}'".format(requisition_id),
        )

    # end method definition

    def create_goods_movement(self, movement: SAPGoodsMovementModel | dict) -> dict | None:
        """Post an SAP goods movement (material document with its items) - e.g. a goods receipt for a purchase order.

        Args:
            movement (SAPGoodsMovementModel | dict):
                The data. A dictionary is validated against the SAPGoodsMovementModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created goods movement as returned by SAP (including "MaterialDocument" and "MaterialDocumentYear") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_MATERIAL_DOCUMENT_SRV",
            entity_set="A_MaterialDocumentHeader",
            model=SAPGoodsMovementModel,
            data=movement,
            key_fields=["MaterialDocument", "MaterialDocumentYear"],
            label="goods movement",
        )

    # end method definition

    def iter_goods_movements(
        self, query: SAPGoodsMovementQueryModel | None = None
    ) -> SAPODataIterator[SAPGoodsMovementResponseModel]:
        """Iterate over SAP goods movements - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPGoodsMovementQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all goods movements).

        Returns:
            SAPODataIterator[SAPGoodsMovementResponseModel]:
                The iterator over the goods movements.

        """

        return self._iter_odata_collection(
            service="API_MATERIAL_DOCUMENT_SRV",
            entity_set="A_MaterialDocumentHeader",
            model=SAPGoodsMovementResponseModel,
            query=query or SAPGoodsMovementQueryModel(),
            label="goods movements",
        )

    # end method definition

    def get_goods_movements(
        self, query: SAPGoodsMovementQueryModel | None = None
    ) -> list[SAPGoodsMovementResponseModel] | None:
        """Get SAP goods movements as a list.

        All matching goods movements are read (page by page, see iter_goods_movements()) and returned at once.
        For very large result sets prefer iter_goods_movements().

        Args:
            query (SAPGoodsMovementQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all goods movements).

        Returns:
            list[SAPGoodsMovementResponseModel] | None:
                The goods movements (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_goods_movements(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP goods movements.", len(results))

        return results

    # end method definition

    def get_goods_movement(
        self,
        document_year: str,
        document: str,
        expand_items: bool = True,
    ) -> SAPGoodsMovementResponseModel | None:
        """Get a single SAP material document (goods movement).

        Args:
            document_year (str):
                The year of the material document, e.g. "2026".
            document (str):
                The material document number, e.g. "4900000123".
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPGoodsMovementResponseModel | None:
                The material document or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_MATERIAL_DOCUMENT_SRV",
            entity_path="A_MaterialDocumentHeader(MaterialDocumentYear='{}',MaterialDocument='{}')".format(
                document_year,
                document,
            ),
            model=SAPGoodsMovementResponseModel,
            params={"$expand": "to_MaterialDocumentItem"} if expand_items else None,
            label="material document -> {}/{}".format(document, document_year),
        )

    # end method definition

    def cancel_goods_movement(
        self,
        document_year: str,
        document: str,
        item: str | None = None,
        posting_date: date | None = None,
    ) -> dict | None:
        """Cancel (reverse) an SAP material document or a single item of it.

        SAP posts a reversal material document - the original document is not changed.

        Args:
            document_year (str):
                The year of the material document, e.g. "2026".
            document (str):
                The material document number, e.g. "4900000123".
            item (str | None, optional):
                The item to cancel, e.g. "1". Defaults to None (cancel all items).
            posting_date (date | None, optional):
                The posting date of the reversal. Defaults to None (today).

        Returns:
            dict | None:
                The reversal material document (header or item) or None in case of an error.

        """

        return self._call_odata_function(
            service="API_MATERIAL_DOCUMENT_SRV",
            function="CancelItem" if item else "Cancel",
            parameters={
                "MaterialDocumentYear": document_year,
                "MaterialDocument": document,
                "MaterialDocumentItem": item.zfill(4) if item else None,
                "PostingDate": posting_date,
            },
            label="cancel material document -> {}/{}{}".format(
                document, document_year, " item " + item if item else ""
            ),
        )

    # end method definition

    def create_maintenance_order_confirmation(
        self, confirmation: SAPMaintenanceOrderConfirmationModel | dict
    ) -> dict | None:
        """Confirm work (time, final confirmation) on an SAP maintenance order operation.

        Args:
            confirmation (SAPMaintenanceOrderConfirmationModel | dict):
                The data. A dictionary is validated against the SAPMaintenanceOrderConfirmationModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created maintenance order confirmation as returned by SAP (including "MaintOrderConf" and "MaintOrderConfCntrValue") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_MAINTORDERCONFIRMATION",
            entity_set="MaintOrderConfirmation",
            model=SAPMaintenanceOrderConfirmationModel,
            data=confirmation,
            key_fields=["MaintOrderConf", "MaintOrderConfCntrValue"],
            label="maintenance order confirmation",
        )

    # end method definition

    def iter_maintenance_order_confirmations(
        self, query: SAPMaintenanceOrderConfirmationQueryModel | None = None
    ) -> SAPODataIterator[SAPMaintenanceOrderConfirmationResponseModel]:
        """Iterate over SAP maintenance order confirmations - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPMaintenanceOrderConfirmationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all maintenance order confirmations).

        Returns:
            SAPODataIterator[SAPMaintenanceOrderConfirmationResponseModel]:
                The iterator over the maintenance order confirmations.

        """

        return self._iter_odata_collection(
            service="API_MAINTORDERCONFIRMATION",
            entity_set="MaintOrderConfirmation",
            model=SAPMaintenanceOrderConfirmationResponseModel,
            query=query or SAPMaintenanceOrderConfirmationQueryModel(),
            label="maintenance order confirmations",
        )

    # end method definition

    def get_maintenance_order_confirmations(
        self, query: SAPMaintenanceOrderConfirmationQueryModel | None = None
    ) -> list[SAPMaintenanceOrderConfirmationResponseModel] | None:
        """Get SAP maintenance order confirmations as a list.

        All matching maintenance order confirmations are read (page by page, see iter_maintenance_order_confirmations()) and returned at once.
        For very large result sets prefer iter_maintenance_order_confirmations().

        Args:
            query (SAPMaintenanceOrderConfirmationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all maintenance order confirmations).

        Returns:
            list[SAPMaintenanceOrderConfirmationResponseModel] | None:
                The maintenance order confirmations (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_maintenance_order_confirmations(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP maintenance order confirmations.", len(results))

        return results

    # end method definition

    def get_maintenance_order_confirmation(
        self,
        confirmation_id: str,
        counter: str,
    ) -> SAPMaintenanceOrderConfirmationResponseModel | None:
        """Get a single SAP maintenance order confirmation.

        Args:
            confirmation_id (str):
                The confirmation number (of the operation), e.g. "1234".
            counter (str):
                The confirmation counter, e.g. "1".

        Returns:
            SAPMaintenanceOrderConfirmationResponseModel | None:
                The confirmation or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_MAINTORDERCONFIRMATION",
            entity_path="MaintOrderConfirmation(MaintOrderConf='{}',MaintOrderConfCntrValue='{}')".format(
                confirmation_id,
                counter,
            ),
            model=SAPMaintenanceOrderConfirmationResponseModel,
            params=None,
            label="maintenance order confirmation -> {}/{}".format(confirmation_id, counter),
        )

    # end method definition

    def cancel_maintenance_order_confirmation(self, confirmation_id: str, counter: str) -> bool:
        """Cancel an SAP maintenance order confirmation.

        Args:
            confirmation_id (str):
                The confirmation number (of the operation), e.g. "1234".
            counter (str):
                The confirmation counter, e.g. "1".

        Returns:
            bool:
                True if the confirmation has been cancelled, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_MAINTORDERCONFIRMATION",
            function="CancelMaintOrderConfirmation",
            parameters={"MaintOrderConf": confirmation_id, "MaintOrderConfCntrValue": counter},
            label="cancel maintenance order confirmation -> {}/{}".format(confirmation_id, counter),
        )

        return result is not None

    # end method definition

    def create_maintenance_plan(self, plan: SAPMaintenancePlanModel | dict) -> dict | None:
        """Create an SAP maintenance plan with its cycles and maintenance items (scheduling is started separately).

        Args:
            plan (SAPMaintenancePlanModel | dict):
                The data. A dictionary is validated against the SAPMaintenancePlanModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created maintenance plan as returned by SAP (including "MaintenancePlan") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_MAINTENANCEPLAN",
            entity_set="MaintenancePlan",
            model=SAPMaintenancePlanModel,
            data=plan,
            key_fields=["MaintenancePlan"],
            label="maintenance plan",
        )

    # end method definition

    def iter_maintenance_plans(
        self, query: SAPMaintenancePlanQueryModel | None = None
    ) -> SAPODataIterator[SAPMaintenancePlanResponseModel]:
        """Iterate over SAP maintenance plans - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPMaintenancePlanQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all maintenance plans).

        Returns:
            SAPODataIterator[SAPMaintenancePlanResponseModel]:
                The iterator over the maintenance plans.

        """

        return self._iter_odata_collection(
            service="API_MAINTENANCEPLAN",
            entity_set="MaintenancePlan",
            model=SAPMaintenancePlanResponseModel,
            query=query or SAPMaintenancePlanQueryModel(),
            label="maintenance plans",
        )

    # end method definition

    def get_maintenance_plans(
        self, query: SAPMaintenancePlanQueryModel | None = None
    ) -> list[SAPMaintenancePlanResponseModel] | None:
        """Get SAP maintenance plans as a list.

        All matching maintenance plans are read (page by page, see iter_maintenance_plans()) and returned at once.
        For very large result sets prefer iter_maintenance_plans().

        Args:
            query (SAPMaintenancePlanQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all maintenance plans).

        Returns:
            list[SAPMaintenancePlanResponseModel] | None:
                The maintenance plans (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_maintenance_plans(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP maintenance plans.", len(results))

        return results

    # end method definition

    def get_maintenance_plan(self, plan_id: str, expand_items: bool = True) -> SAPMaintenancePlanResponseModel | None:
        """Get a single SAP maintenance plan.

        Args:
            plan_id (str):
                The maintenance plan number, e.g. "10".
            expand_items (bool, optional):
                Whether to read the cycles and items as well. Defaults to True.

        Returns:
            SAPMaintenancePlanResponseModel | None:
                The maintenance plan or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_MAINTENANCEPLAN",
            entity_path="MaintenancePlan('{}')".format(plan_id.replace("'", "''")),
            model=SAPMaintenancePlanResponseModel,
            params={"$expand": "to_MaintenanceCycle,to_Item"} if expand_items else None,
            label="maintenance plan -> '{}'".format(plan_id),
        )

    # end method definition

    def update_maintenance_plan(self, plan_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP maintenance plan.

        The changes are validated with the field definitions of SAPMaintenancePlanModel. Cycles and items cannot be changed with this method.

        Args:
            plan_id (str):
                The maintenance plan number, e.g. "10".
            changes (dict):
                The fields to change - snake case attribute names of SAPMaintenancePlanModel or OData property names.

        Returns:
            bool:
                True if the maintenance plan has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_MAINTENANCEPLAN",
            entity_path="MaintenancePlan('{}')".format(plan_id.replace("'", "''")),
            model=SAPMaintenancePlanModel,
            changes=changes,
            label="maintenance plan -> '{}'".format(plan_id),
        )

    # end method definition

    def change_maintenance_plan_status(
        self,
        plan_id: str,
        action: SAPMaintenancePlanAction,
        parameters: dict | None = None,
    ) -> bool:
        """Change the status of an SAP maintenance plan (e.g. start scheduling, activate or deactivate).

        Args:
            plan_id (str):
                The maintenance plan number, e.g. "10".
            action (SAPMaintenancePlanAction):
                The status action, e.g. SAPMaintenancePlanAction.START_SCHEDULING.
            parameters (dict | None, optional):
                Additional (optional) parameters of the action with their OData names. Defaults to None.

        Returns:
            bool:
                True if the status has been changed, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_MAINTENANCEPLAN",
            function=str(action),
            parameters={"MaintenancePlan": plan_id, **(parameters or {})},
            label="{} maintenance plan -> '{}'".format(action.name.lower().replace("_", " "), plan_id),
        )

        return result is not None

    # end method definition

    def create_planned_order(self, order: SAPPlannedOrderModel | dict) -> dict | None:
        """Create an SAP planned order (components and capacities are determined by SAP).

        Args:
            order (SAPPlannedOrderModel | dict):
                The data. A dictionary is validated against the SAPPlannedOrderModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created planned order as returned by SAP (including "PlannedOrder") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_PLANNEDORDER",
            entity_set="PlannedOrderHeader",
            model=SAPPlannedOrderModel,
            data=order,
            key_fields=["PlannedOrder"],
            label="planned order",
        )

    # end method definition

    def iter_planned_orders(
        self, query: SAPPlannedOrderQueryModel | None = None
    ) -> SAPODataIterator[SAPPlannedOrderResponseModel]:
        """Iterate over SAP planned orders - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPPlannedOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all planned orders).

        Returns:
            SAPODataIterator[SAPPlannedOrderResponseModel]:
                The iterator over the planned orders.

        """

        return self._iter_odata_collection(
            service="API_PLANNEDORDER",
            entity_set="PlannedOrderHeader",
            model=SAPPlannedOrderResponseModel,
            query=query or SAPPlannedOrderQueryModel(),
            label="planned orders",
        )

    # end method definition

    def get_planned_orders(
        self, query: SAPPlannedOrderQueryModel | None = None
    ) -> list[SAPPlannedOrderResponseModel] | None:
        """Get SAP planned orders as a list.

        All matching planned orders are read (page by page, see iter_planned_orders()) and returned at once.
        For very large result sets prefer iter_planned_orders().

        Args:
            query (SAPPlannedOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all planned orders).

        Returns:
            list[SAPPlannedOrderResponseModel] | None:
                The planned orders (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_planned_orders(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP planned orders.", len(results))

        return results

    # end method definition

    def get_planned_order(self, planned_order_id: str) -> SAPPlannedOrderResponseModel | None:
        """Get a single SAP planned order.

        Args:
            planned_order_id (str):
                The planned order number, e.g. "1234".

        Returns:
            SAPPlannedOrderResponseModel | None:
                The planned order or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_PLANNEDORDER",
            entity_path="PlannedOrderHeader('{}')".format(planned_order_id.replace("'", "''")),
            model=SAPPlannedOrderResponseModel,
            params=None,
            label="planned order -> '{}'".format(planned_order_id),
        )

    # end method definition

    def update_planned_order(self, planned_order_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP planned order.

        The changes are validated with the field definitions of SAPPlannedOrderModel.

        Args:
            planned_order_id (str):
                The planned order number, e.g. "1234".
            changes (dict):
                The fields to change - snake case attribute names of SAPPlannedOrderModel or OData property names.

        Returns:
            bool:
                True if the planned order has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_PLANNEDORDER",
            entity_path="PlannedOrderHeader('{}')".format(planned_order_id.replace("'", "''")),
            model=SAPPlannedOrderModel,
            changes=changes,
            label="planned order -> '{}'".format(planned_order_id),
        )

    # end method definition

    def delete_planned_order(self, planned_order_id: str) -> bool:
        """Delete an SAP planned order.

        Args:
            planned_order_id (str):
                The planned order number, e.g. "1234".

        Returns:
            bool:
                True if the planned order has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_PLANNEDORDER",
            entity_path="PlannedOrderHeader('{}')".format(planned_order_id.replace("'", "''")),
            label="planned order -> '{}'".format(planned_order_id),
        )

    # end method definition

    def schedule_planned_order(self, planned_order_id: str) -> bool:
        """Schedule an SAP planned order (determine its dates based on the routing / capacities).

        Args:
            planned_order_id (str):
                The planned order number, e.g. "1234".

        Returns:
            bool:
                True if the planned order has been scheduled, False in case of an error.

        """

        result = self._call_odata_bound_action(
            service="API_PLANNEDORDER",
            entity_path="PlannedOrderHeader('{}')".format(planned_order_id.replace("'", "''")),
            action="SchedulePlannedOrder",
            namespace=PLANNED_ORDER_ACTION_NAMESPACE,
            parameters=None,
            label="schedule planned order -> '{}'".format(planned_order_id),
        )

        return result is not None

    # end method definition

    def create_production_order(self, order: SAPProductionOrderModel | dict, release: bool = False) -> dict | None:
        """Create an SAP production order - optionally released right away.

        SAP determines operations and components from the routing / production version
        and the bill of material. To create a production order from a planned order
        instead, see create_production_order_from_planned_order().

        Args:
            order (SAPProductionOrderModel | dict):
                The production order data. A dictionary is validated against the
                SAPProductionOrderModel (snake case attribute names or OData property names).
            release (bool, optional):
                Whether to release the production order after the creation. Defaults to False.

        Returns:
            dict | None:
                The created production order as returned by SAP (including the number in
                "ManufacturingOrder") or None in case of an error. If the release fails, the
                created order is still returned (an error is logged).

        """

        created = self._create_odata_entity(
            service="API_PRODUCTION_ORDER_2_SRV",
            entity_set="A_ProductionOrder_2",
            model=SAPProductionOrderModel,
            data=order,
            key_fields=["ManufacturingOrder"],
            label="production order",
        )
        if created and release:
            self.change_production_order_status(created["ManufacturingOrder"], SAPProductionOrderAction.RELEASE)

        return created

    # end method definition

    def convert_planned_order(
        self,
        planned_order_id: str,
        order_type: str | None = None,
        production_order_id: str | None = None,
        release: bool = False,
    ) -> str | None:
        """Convert an SAP planned order into a production order - optionally released right away.

        SAP deletes the planned order after the conversion.

        Args:
            planned_order_id (str):
                The planned order number, e.g. "1234".
            order_type (str | None, optional):
                The production order type, e.g. "PP01". Defaults to None (SAP default).
            production_order_id (str | None, optional):
                The production order number - only for external number assignment.
                Defaults to None (SAP assigns the number).
            release (bool, optional):
                Whether to release the production order after the conversion. Defaults to False.

        Returns:
            str | None:
                The number of the production order or None in case of an error.

        """

        result = self._call_odata_function(
            service="API_PRODUCTION_ORDER_2_SRV",
            function="ConvertPlndOrder",
            parameters={
                "PlannedOrder": planned_order_id,
                "ManufacturingOrderType": order_type,
                "ManufacturingOrder": production_order_id,
            },
            label="convert planned order -> '{}' into a production order".format(planned_order_id),
        )
        if result is None:
            return None

        order_id = result.get("ManufacturingOrder") or production_order_id
        if not order_id:
            self.log_error(
                "Conversion of planned order -> '%s' did not return a production order number; result -> %s",
                planned_order_id,
                str(result),
            )
            return None
        self.logger.info(
            "Planned order -> '%s' has been converted into production order -> '%s'.", planned_order_id, order_id
        )

        if release:
            self.change_production_order_status(order_id, SAPProductionOrderAction.RELEASE)

        return order_id

    # end method definition

    def create_production_order_from_planned_order(
        self,
        planned_order: SAPPlannedOrderModel | dict,
        order_type: str | None = None,
        release: bool = True,
    ) -> str | None:
        """Create a production order via a planned order: create the planned order, convert and release it.

        This mirrors the typical SAP process (planning -> production). If the conversion
        fails, the planned order remains in SAP (an error with its number is logged).

        Args:
            planned_order (SAPPlannedOrderModel | dict):
                The planned order data (see create_planned_order()).
            order_type (str | None, optional):
                The production order type, e.g. "PP01". Defaults to None (SAP default).
            release (bool, optional):
                Whether to release the production order. Defaults to True.

        Returns:
            str | None:
                The number of the production order or None in case of an error.

        """

        created = self.create_planned_order(order=planned_order)
        if not created:
            return None

        order_id = self.convert_planned_order(
            planned_order_id=created["PlannedOrder"],
            order_type=order_type,
            release=release,
        )
        if not order_id:
            self.logger.error(
                "Planned order -> '%s' has been created but could not be converted!", created["PlannedOrder"]
            )

        return order_id

    # end method definition

    def iter_production_orders(
        self, query: SAPProductionOrderQueryModel | None = None
    ) -> SAPODataIterator[SAPProductionOrderResponseModel]:
        """Iterate over SAP production orders - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPProductionOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all production orders).

        Returns:
            SAPODataIterator[SAPProductionOrderResponseModel]:
                The iterator over the production orders.

        """

        return self._iter_odata_collection(
            service="API_PRODUCTION_ORDER_2_SRV",
            entity_set="A_ProductionOrder_2",
            model=SAPProductionOrderResponseModel,
            query=query or SAPProductionOrderQueryModel(),
            label="production orders",
        )

    # end method definition

    def get_production_orders(
        self, query: SAPProductionOrderQueryModel | None = None
    ) -> list[SAPProductionOrderResponseModel] | None:
        """Get SAP production orders as a list.

        All matching production orders are read (page by page, see iter_production_orders()) and returned at once.
        For very large result sets prefer iter_production_orders().

        Args:
            query (SAPProductionOrderQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all production orders).

        Returns:
            list[SAPProductionOrderResponseModel] | None:
                The production orders (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_production_orders(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP production orders.", len(results))

        return results

    # end method definition

    def get_production_order(self, order_id: str, expand_items: bool = True) -> SAPProductionOrderResponseModel | None:
        """Get a single SAP production order.

        Args:
            order_id (str):
                The production order number, e.g. "1000123".
            expand_items (bool, optional):
                Whether to read the operations and statuses as well. Defaults to True.

        Returns:
            SAPProductionOrderResponseModel | None:
                The production order or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_PRODUCTION_ORDER_2_SRV",
            entity_path="A_ProductionOrder_2('{}')".format(order_id.replace("'", "''")),
            model=SAPProductionOrderResponseModel,
            params={"$expand": "to_ProductionOrderOperation,to_ProductionOrderStatus"} if expand_items else None,
            label="production order -> '{}'".format(order_id),
        )

    # end method definition

    def update_production_order(self, order_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP production order.

        The changes are validated with the field definitions of SAPProductionOrderModel. SAP allows changing scheduling, date / time and quantity information.

        Args:
            order_id (str):
                The production order number, e.g. "1000123".
            changes (dict):
                The fields to change - snake case attribute names of SAPProductionOrderModel or OData property names.

        Returns:
            bool:
                True if the production order has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_PRODUCTION_ORDER_2_SRV",
            entity_path="A_ProductionOrder_2('{}')".format(order_id.replace("'", "''")),
            model=SAPProductionOrderModel,
            changes=changes,
            label="production order -> '{}'".format(order_id),
        )

    # end method definition

    def change_production_order_status(
        self,
        order_id: str,
        action: SAPProductionOrderAction,
        parameters: dict | None = None,
    ) -> bool:
        """Change the status of an SAP production order (e.g. release, technically complete or close).

        Args:
            order_id (str):
                The production order number, e.g. "1000123".
            action (SAPProductionOrderAction):
                The status action, e.g. SAPProductionOrderAction.RELEASE.
            parameters (dict | None, optional):
                Additional (optional) parameters of the action with their OData names. Defaults to None.

        Returns:
            bool:
                True if the status has been changed, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_PRODUCTION_ORDER_2_SRV",
            function=str(action),
            parameters={"ManufacturingOrder": order_id, **(parameters or {})},
            label="{} production order -> '{}'".format(action.name.lower().replace("_", " "), order_id),
        )

        return result is not None

    # end method definition

    def iter_plants(self, query: SAPPlantQueryModel | None = None) -> SAPODataIterator[SAPPlantResponseModel]:
        """Iterate over SAP plants - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPPlantQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all plants).

        Returns:
            SAPODataIterator[SAPPlantResponseModel]:
                The iterator over the plants.

        """

        return self._iter_odata_collection(
            service="API_PLANT_2",
            entity_set="Plant",
            model=SAPPlantResponseModel,
            query=query or SAPPlantQueryModel(),
            label="plants",
        )

    # end method definition

    def get_plants(self, query: SAPPlantQueryModel | None = None) -> list[SAPPlantResponseModel] | None:
        """Get SAP plants as a list.

        All matching plants are read (page by page, see iter_plants()) and returned at once.
        For very large result sets prefer iter_plants().

        Args:
            query (SAPPlantQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all plants).

        Returns:
            list[SAPPlantResponseModel] | None:
                The plants (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_plants(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP plants.", len(results))

        return results

    # end method definition

    def get_plant(self, plant_id: str) -> SAPPlantResponseModel | None:
        """Get a single SAP plant (master data).

        Args:
            plant_id (str):
                The plant, e.g. "1000".

        Returns:
            SAPPlantResponseModel | None:
                The plant or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_PLANT_2",
            entity_path="Plant('{}')".format(self._quote_key(plant_id)),
            model=SAPPlantResponseModel,
            params=None,
            label="plant -> '{}'".format(plant_id),
        )

    # end method definition

    def iter_storage_locations(
        self, query: SAPStorageLocationQueryModel | None = None
    ) -> SAPODataIterator[SAPStorageLocationResponseModel]:
        """Iterate over SAP storage locations - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPStorageLocationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all storage locations).

        Returns:
            SAPODataIterator[SAPStorageLocationResponseModel]:
                The iterator over the storage locations.

        """

        return self._iter_odata_collection(
            service="API_STORAGELOCATION_SRV",
            entity_set="StorageLocation",
            model=SAPStorageLocationResponseModel,
            query=query or SAPStorageLocationQueryModel(),
            label="storage locations",
        )

    # end method definition

    def get_storage_locations(
        self, query: SAPStorageLocationQueryModel | None = None
    ) -> list[SAPStorageLocationResponseModel] | None:
        """Get SAP storage locations as a list.

        All matching storage locations are read (page by page, see iter_storage_locations()) and returned at once.
        For very large result sets prefer iter_storage_locations().

        Args:
            query (SAPStorageLocationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all storage locations).

        Returns:
            list[SAPStorageLocationResponseModel] | None:
                The storage locations (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_storage_locations(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP storage locations.", len(results))

        return results

    # end method definition

    def get_storage_location(self, plant: str, storage_location: str) -> SAPStorageLocationResponseModel | None:
        """Get a single SAP storage location (master data).

        Args:
            plant (str):
                The plant, e.g. "1000".
            storage_location (str):
                The storage location, e.g. "0001".

        Returns:
            SAPStorageLocationResponseModel | None:
                The storage location or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_STORAGELOCATION_SRV",
            entity_path="StorageLocation(Plant='{}',StorageLocation='{}')".format(
                self._quote_key(plant), self._quote_key(storage_location)
            ),
            model=SAPStorageLocationResponseModel,
            params=None,
            label="storage location -> {}/{}".format(plant, storage_location),
        )

    # end method definition

    def iter_products(self, query: SAPProductQueryModel | None = None) -> SAPODataIterator[SAPProductResponseModel]:
        """Iterate over SAP products - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPProductQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all products).

        Returns:
            SAPODataIterator[SAPProductResponseModel]:
                The iterator over the products.

        """

        return self._iter_odata_collection(
            service="API_PRODUCT_SRV",
            entity_set="A_Product",
            model=SAPProductResponseModel,
            query=query or SAPProductQueryModel(),
            label="products",
        )

    # end method definition

    def get_products(self, query: SAPProductQueryModel | None = None) -> list[SAPProductResponseModel] | None:
        """Get SAP products as a list.

        All matching products are read (page by page, see iter_products()) and returned at once.
        For very large result sets prefer iter_products().

        Args:
            query (SAPProductQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all products).

        Returns:
            list[SAPProductResponseModel] | None:
                The products (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_products(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP products.", len(results))

        return results

    # end method definition

    def get_product(self, product_id: str, expand_items: bool = True) -> SAPProductResponseModel | None:
        """Get a single SAP product (master data).

        Args:
            product_id (str):
                The product (material) number, e.g. "P-100".
            expand_items (bool, optional):
                Whether to read the descriptions and plant data as well. Defaults to True.

        Returns:
            SAPProductResponseModel | None:
                The product or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_PRODUCT_SRV",
            entity_path="A_Product('{}')".format(self._quote_key(product_id)),
            model=SAPProductResponseModel,
            params={"$expand": "to_Description,to_Plant"} if expand_items else None,
            label="product -> '{}'".format(product_id),
        )

    # end method definition

    def iter_production_versions(
        self, query: SAPProductionVersionQueryModel | None = None
    ) -> SAPODataIterator[SAPProductionVersionResponseModel]:
        """Iterate over SAP production versions - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPProductionVersionQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all production versions).

        Returns:
            SAPODataIterator[SAPProductionVersionResponseModel]:
                The iterator over the production versions.

        """

        return self._iter_odata_collection(
            service="API_PRODUCTION_VERSION",
            entity_set="ProductionVersion",
            model=SAPProductionVersionResponseModel,
            query=query or SAPProductionVersionQueryModel(),
            label="production versions",
        )

    # end method definition

    def get_production_versions(
        self, query: SAPProductionVersionQueryModel | None = None
    ) -> list[SAPProductionVersionResponseModel] | None:
        """Get SAP production versions as a list.

        All matching production versions are read (page by page, see iter_production_versions()) and returned at once.
        For very large result sets prefer iter_production_versions().

        Args:
            query (SAPProductionVersionQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all production versions).

        Returns:
            list[SAPProductionVersionResponseModel] | None:
                The production versions (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_production_versions(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP production versions.", len(results))

        return results

    # end method definition

    def get_production_version(
        self, material: str, plant: str, production_version: str
    ) -> SAPProductionVersionResponseModel | None:
        """Get a single SAP production version (master data).

        Args:
            material (str):
                The material, e.g. "P-100".
            plant (str):
                The plant, e.g. "1000".
            production_version (str):
                The production version, e.g. "0001".

        Returns:
            SAPProductionVersionResponseModel | None:
                The production version or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_PRODUCTION_VERSION",
            entity_path="ProductionVersion(Material='{}',Plant='{}',ProductionVersion='{}')".format(
                self._quote_key(material), self._quote_key(plant), self._quote_key(production_version)
            ),
            model=SAPProductionVersionResponseModel,
            params=None,
            label="production version -> {}/{}/{}".format(material, plant, production_version),
        )

    # end method definition

    def iter_work_centers(
        self, query: SAPWorkCenterQueryModel | None = None
    ) -> SAPODataIterator[SAPWorkCenterResponseModel]:
        """Iterate over SAP work centers - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPWorkCenterQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all work centers).

        Returns:
            SAPODataIterator[SAPWorkCenterResponseModel]:
                The iterator over the work centers.

        """

        return self._iter_odata_collection(
            service="API_WORK_CENTERS",
            entity_set="A_WorkCenters",
            model=SAPWorkCenterResponseModel,
            query=query or SAPWorkCenterQueryModel(),
            label="work centers",
        )

    # end method definition

    def get_work_centers(self, query: SAPWorkCenterQueryModel | None = None) -> list[SAPWorkCenterResponseModel] | None:
        """Get SAP work centers as a list.

        All matching work centers are read (page by page, see iter_work_centers()) and returned at once.
        For very large result sets prefer iter_work_centers().

        Args:
            query (SAPWorkCenterQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all work centers).

        Returns:
            list[SAPWorkCenterResponseModel] | None:
                The work centers (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_work_centers(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP work centers.", len(results))

        return results

    # end method definition

    def get_work_center(self, work_center: str, plant: str) -> SAPWorkCenterResponseModel | None:
        """Get a single SAP work center (master data).

        The work center is identified by its code and plant (the OData key is an internal ID).

        Args:
            work_center (str):
                The work center, e.g. "1904".
            plant (str):
                The plant of the work center, e.g. "3000".

        Returns:
            SAPWorkCenterResponseModel | None:
                The work center or None if it does not exist or in case of an error.

        """

        entries = self.iter_work_centers(
            query=SAPWorkCenterQueryModel(work_center_ids=[work_center], plant=plant, limit=1),
        )
        entry = next(entries, None)
        if entry is None and not entries.failed:
            self.logger.warning("Cannot find SAP work center -> %s/%s", work_center, plant)

        return entry

    # end method definition

    def iter_equipments(
        self, query: SAPEquipmentQueryModel | None = None
    ) -> SAPODataIterator[SAPEquipmentResponseModel]:
        """Iterate over SAP equipments - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPEquipmentQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all equipments).

        Returns:
            SAPODataIterator[SAPEquipmentResponseModel]:
                The iterator over the equipments.

        """

        return self._iter_odata_collection(
            service="API_EQUIPMENT",
            entity_set="Equipment",
            model=SAPEquipmentResponseModel,
            query=query or SAPEquipmentQueryModel(),
            label="equipments",
        )

    # end method definition

    def get_equipments(self, query: SAPEquipmentQueryModel | None = None) -> list[SAPEquipmentResponseModel] | None:
        """Get SAP equipments as a list.

        All matching equipments are read (page by page, see iter_equipments()) and returned at once.
        For very large result sets prefer iter_equipments().

        Args:
            query (SAPEquipmentQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all equipments).

        Returns:
            list[SAPEquipmentResponseModel] | None:
                The equipments (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_equipments(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP equipments.", len(results))

        return results

    # end method definition

    def get_equipment(self, equipment_id: str) -> SAPEquipmentResponseModel | None:
        """Get a single SAP equipment (master data).

        Equipment data is time dependent - the currently valid version (latest validity end date) is returned.

        Args:
            equipment_id (str):
                The equipment number, e.g. "210100001".

        Returns:
            SAPEquipmentResponseModel | None:
                The equipment or None if it does not exist or in case of an error.

        """

        # Sorted with the latest validity period first:
        entries = self.iter_equipments(query=SAPEquipmentQueryModel(equipment_ids=[equipment_id], limit=1))
        entry = next(entries, None)
        if entry is None and not entries.failed:
            self.logger.warning("Cannot find SAP equipment -> '%s'", equipment_id)

        return entry

    # end method definition

    def iter_functional_locations(
        self, query: SAPFunctionalLocationQueryModel | None = None
    ) -> SAPODataIterator[SAPFunctionalLocationResponseModel]:
        """Iterate over SAP functional locations - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPFunctionalLocationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all functional locations).

        Returns:
            SAPODataIterator[SAPFunctionalLocationResponseModel]:
                The iterator over the functional locations.

        """

        return self._iter_odata_collection(
            service="API_FUNCTIONALLOCATION",
            entity_set="FunctionalLocation",
            model=SAPFunctionalLocationResponseModel,
            query=query or SAPFunctionalLocationQueryModel(),
            label="functional locations",
        )

    # end method definition

    def get_functional_locations(
        self, query: SAPFunctionalLocationQueryModel | None = None
    ) -> list[SAPFunctionalLocationResponseModel] | None:
        """Get SAP functional locations as a list.

        All matching functional locations are read (page by page, see iter_functional_locations()) and returned at once.
        For very large result sets prefer iter_functional_locations().

        Args:
            query (SAPFunctionalLocationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all functional locations).

        Returns:
            list[SAPFunctionalLocationResponseModel] | None:
                The functional locations (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_functional_locations(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP functional locations.", len(results))

        return results

    # end method definition

    def get_functional_location(self, functional_location_id: str) -> SAPFunctionalLocationResponseModel | None:
        """Get a single SAP functional location (master data).

        Args:
            functional_location_id (str):
                The (internal) functional location ID - see also get_functional_locations() with a filter on
                "FunctionalLocationLabelName" to read by label.

        Returns:
            SAPFunctionalLocationResponseModel | None:
                The functional location or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_FUNCTIONALLOCATION",
            entity_path="FunctionalLocation('{}')".format(self._quote_key(functional_location_id)),
            model=SAPFunctionalLocationResponseModel,
            params=None,
            label="functional location -> '{}'".format(functional_location_id),
        )

    # end method definition

    def iter_business_partners(
        self, query: SAPBusinessPartnerQueryModel | None = None
    ) -> SAPODataIterator[SAPBusinessPartnerResponseModel]:
        """Iterate over SAP business partners - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPBusinessPartnerQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all business partners).

        Returns:
            SAPODataIterator[SAPBusinessPartnerResponseModel]:
                The iterator over the business partners.

        """

        return self._iter_odata_collection(
            service="API_BUSINESS_PARTNER",
            entity_set="A_BusinessPartner",
            model=SAPBusinessPartnerResponseModel,
            query=query or SAPBusinessPartnerQueryModel(),
            label="business partners",
        )

    # end method definition

    def get_business_partners(
        self, query: SAPBusinessPartnerQueryModel | None = None
    ) -> list[SAPBusinessPartnerResponseModel] | None:
        """Get SAP business partners as a list.

        All matching business partners are read (page by page, see iter_business_partners()) and returned at once.
        For very large result sets prefer iter_business_partners().

        Args:
            query (SAPBusinessPartnerQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all business partners).

        Returns:
            list[SAPBusinessPartnerResponseModel] | None:
                The business partners (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_business_partners(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP business partners.", len(results))

        return results

    # end method definition

    def get_business_partner(
        self, business_partner_id: str, expand_items: bool = True
    ) -> SAPBusinessPartnerResponseModel | None:
        """Get a single SAP business partner (master data).

        Args:
            business_partner_id (str):
                The business partner number, e.g. "10300001".
            expand_items (bool, optional):
                Whether to read the roles as well. Defaults to True.

        Returns:
            SAPBusinessPartnerResponseModel | None:
                The business partner or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_BUSINESS_PARTNER",
            entity_path="A_BusinessPartner('{}')".format(self._quote_key(business_partner_id)),
            model=SAPBusinessPartnerResponseModel,
            params={"$expand": "to_BusinessPartnerRole"} if expand_items else None,
            label="business partner -> '{}'".format(business_partner_id),
        )

    # end method definition

    def iter_customers(
        self, query: SAPCustomerQueryModel | None = None
    ) -> SAPODataIterator[SAPBusinessPartnerResponseModel]:
        """Iterate over SAP customers - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPCustomerQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all customers).

        Returns:
            SAPODataIterator[SAPBusinessPartnerResponseModel]:
                The iterator over the customers.

        """

        return self._iter_odata_collection(
            service="API_BUSINESS_PARTNER",
            entity_set="A_BusinessPartner",
            model=SAPBusinessPartnerResponseModel,
            query=query or SAPCustomerQueryModel(),
            label="customers",
        )

    # end method definition

    def get_customers(self, query: SAPCustomerQueryModel | None = None) -> list[SAPBusinessPartnerResponseModel] | None:
        """Get SAP customers as a list.

        All matching customers are read (page by page, see iter_customers()) and returned at once.
        For very large result sets prefer iter_customers().

        Args:
            query (SAPCustomerQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all customers).

        Returns:
            list[SAPBusinessPartnerResponseModel] | None:
                The customers (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_customers(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP customers.", len(results))

        return results

    # end method definition

    def get_customer(self, customer_id: str, expand_items: bool = True) -> SAPBusinessPartnerResponseModel | None:
        """Get the business partner of a customer number (master data).

        In S/4HANA customers are business partners with the customer role (customer / vendor
        integration). The customer number (as used in business documents and as business object
        ID of KNA1 business workspaces) is not necessarily the business partner number, so
        the business partner is looked up by its "Customer" property.

        Args:
            customer_id (str):
                The customer number, e.g. "17100001".
            expand_items (bool, optional):
                Whether to read the roles as well. Defaults to True.

        Returns:
            SAPBusinessPartnerResponseModel | None:
                The business partner or None if it does not exist or in case of an error.

        """

        # Two entries to detect ambiguous assignments (there should be exactly one business partner):
        entries = self.get_customers(
            query=SAPCustomerQueryModel(customer_ids=[customer_id], limit=2, expand_items=expand_items)
        )
        if entries is None:
            return None
        if len(entries) > 1:
            self.log_error(
                "SAP customer -> '%s' is assigned to several business partners -> %s",
                customer_id,
                ", ".join(entry.business_partner_id for entry in entries),
            )
            return None
        if not entries:
            self.logger.warning("Cannot find SAP customer -> '%s'", customer_id)
            return None

        return entries[0]

    # end method definition

    def iter_vendors(
        self, query: SAPVendorQueryModel | None = None
    ) -> SAPODataIterator[SAPBusinessPartnerResponseModel]:
        """Iterate over SAP vendors - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPVendorQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all vendors).

        Returns:
            SAPODataIterator[SAPBusinessPartnerResponseModel]:
                The iterator over the vendors.

        """

        return self._iter_odata_collection(
            service="API_BUSINESS_PARTNER",
            entity_set="A_BusinessPartner",
            model=SAPBusinessPartnerResponseModel,
            query=query or SAPVendorQueryModel(),
            label="vendors",
        )

    # end method definition

    def get_vendors(self, query: SAPVendorQueryModel | None = None) -> list[SAPBusinessPartnerResponseModel] | None:
        """Get SAP vendors as a list.

        All matching vendors are read (page by page, see iter_vendors()) and returned at once.
        For very large result sets prefer iter_vendors().

        Args:
            query (SAPVendorQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all vendors).

        Returns:
            list[SAPBusinessPartnerResponseModel] | None:
                The vendors (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_vendors(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP vendors.", len(results))

        return results

    # end method definition

    def get_vendor(self, vendor_id: str, expand_items: bool = True) -> SAPBusinessPartnerResponseModel | None:
        """Get the business partner of a vendor number (master data).

        In S/4HANA vendors are business partners with the vendor role (customer / vendor
        integration). The vendor number (as used in business documents and as business object
        ID of LFA1 business workspaces) is not necessarily the business partner number, so
        the business partner is looked up by its "Supplier" property.

        Args:
            vendor_id (str):
                The vendor number, e.g. "17300001".
            expand_items (bool, optional):
                Whether to read the roles as well. Defaults to True.

        Returns:
            SAPBusinessPartnerResponseModel | None:
                The business partner or None if it does not exist or in case of an error.

        """

        # Two entries to detect ambiguous assignments (there should be exactly one business partner):
        entries = self.get_vendors(
            query=SAPVendorQueryModel(vendor_ids=[vendor_id], limit=2, expand_items=expand_items)
        )
        if entries is None:
            return None
        if len(entries) > 1:
            self.log_error(
                "SAP vendor -> '%s' is assigned to several business partners -> %s",
                vendor_id,
                ", ".join(entry.business_partner_id for entry in entries),
            )
            return None
        if not entries:
            self.logger.warning("Cannot find SAP vendor -> '%s'", vendor_id)
            return None

        return entries[0]

    # end method definition

    def iter_company_codes(
        self, query: SAPCompanyCodeQueryModel | None = None
    ) -> SAPODataIterator[SAPCompanyCodeResponseModel]:
        """Iterate over SAP company codes - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPCompanyCodeQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all company codes).

        Returns:
            SAPODataIterator[SAPCompanyCodeResponseModel]:
                The iterator over the company codes.

        """

        return self._iter_odata_collection(
            service="API_COMPANYCODE_SRV",
            entity_set="A_CompanyCode",
            model=SAPCompanyCodeResponseModel,
            query=query or SAPCompanyCodeQueryModel(),
            label="company codes",
        )

    # end method definition

    def get_company_codes(
        self, query: SAPCompanyCodeQueryModel | None = None
    ) -> list[SAPCompanyCodeResponseModel] | None:
        """Get SAP company codes as a list.

        All matching company codes are read (page by page, see iter_company_codes()) and returned at once.
        For very large result sets prefer iter_company_codes().

        Args:
            query (SAPCompanyCodeQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all company codes).

        Returns:
            list[SAPCompanyCodeResponseModel] | None:
                The company codes (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_company_codes(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP company codes.", len(results))

        return results

    # end method definition

    def get_company_code(self, company_code: str) -> SAPCompanyCodeResponseModel | None:
        """Get a single SAP company code (master data).

        Args:
            company_code (str):
                The company code, e.g. "1000".

        Returns:
            SAPCompanyCodeResponseModel | None:
                The company code or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_COMPANYCODE_SRV",
            entity_path="A_CompanyCode('{}')".format(self._quote_key(company_code)),
            model=SAPCompanyCodeResponseModel,
            params=None,
            label="company code -> '{}'".format(company_code),
        )

    # end method definition

    def iter_sales_organizations(
        self, query: SAPSalesOrganizationQueryModel | None = None
    ) -> SAPODataIterator[SAPSalesOrganizationResponseModel]:
        """Iterate over SAP sales organizations - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPSalesOrganizationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all sales organizations).

        Returns:
            SAPODataIterator[SAPSalesOrganizationResponseModel]:
                The iterator over the sales organizations.

        """

        return self._iter_odata_collection(
            service="API_SALESORGANIZATION_SRV",
            entity_set="A_SalesOrganization",
            model=SAPSalesOrganizationResponseModel,
            query=query or SAPSalesOrganizationQueryModel(),
            label="sales organizations",
        )

    # end method definition

    def get_sales_organizations(
        self, query: SAPSalesOrganizationQueryModel | None = None
    ) -> list[SAPSalesOrganizationResponseModel] | None:
        """Get SAP sales organizations as a list.

        All matching sales organizations are read (page by page, see iter_sales_organizations()) and returned at once.
        For very large result sets prefer iter_sales_organizations().

        Args:
            query (SAPSalesOrganizationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all sales organizations).

        Returns:
            list[SAPSalesOrganizationResponseModel] | None:
                The sales organizations (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_sales_organizations(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP sales organizations.", len(results))

        return results

    # end method definition

    def get_sales_organization(
        self, sales_organization: str, expand_items: bool = True
    ) -> SAPSalesOrganizationResponseModel | None:
        """Get a single SAP sales organization (master data).

        Args:
            sales_organization (str):
                The sales organization, e.g. "1000".
            expand_items (bool, optional):
                Whether to read the names as well. Defaults to True.

        Returns:
            SAPSalesOrganizationResponseModel | None:
                The sales organization or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_SALESORGANIZATION_SRV",
            entity_path="A_SalesOrganization('{}')".format(self._quote_key(sales_organization)),
            model=SAPSalesOrganizationResponseModel,
            params={"$expand": "to_Text"} if expand_items else None,
            label="sales organization -> '{}'".format(sales_organization),
        )

    # end method definition

    def iter_purchasing_organizations(
        self, query: SAPPurchasingOrganizationQueryModel | None = None
    ) -> SAPODataIterator[SAPPurchasingOrganizationResponseModel]:
        """Iterate over SAP purchasing organizations - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPPurchasingOrganizationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all purchasing organizations).

        Returns:
            SAPODataIterator[SAPPurchasingOrganizationResponseModel]:
                The iterator over the purchasing organizations.

        """

        return self._iter_odata_collection(
            service="API_PURCHASINGORGANIZATION",
            entity_set="A_PurchasingOrganization",
            model=SAPPurchasingOrganizationResponseModel,
            query=query or SAPPurchasingOrganizationQueryModel(),
            label="purchasing organizations",
        )

    # end method definition

    def get_purchasing_organizations(
        self, query: SAPPurchasingOrganizationQueryModel | None = None
    ) -> list[SAPPurchasingOrganizationResponseModel] | None:
        """Get SAP purchasing organizations as a list.

        All matching purchasing organizations are read (page by page, see iter_purchasing_organizations()) and returned at once.
        For very large result sets prefer iter_purchasing_organizations().

        Args:
            query (SAPPurchasingOrganizationQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all purchasing organizations).

        Returns:
            list[SAPPurchasingOrganizationResponseModel] | None:
                The purchasing organizations (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_purchasing_organizations(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP purchasing organizations.", len(results))

        return results

    # end method definition

    def get_purchasing_organization(
        self, purchasing_organization: str
    ) -> SAPPurchasingOrganizationResponseModel | None:
        """Get a single SAP purchasing organization (master data).

        Args:
            purchasing_organization (str):
                The purchasing organization, e.g. "1000".

        Returns:
            SAPPurchasingOrganizationResponseModel | None:
                The purchasing organization or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_PURCHASINGORGANIZATION",
            entity_path="A_PurchasingOrganization('{}')".format(self._quote_key(purchasing_organization)),
            model=SAPPurchasingOrganizationResponseModel,
            params=None,
            label="purchasing organization -> '{}'".format(purchasing_organization),
        )

    # end method definition

    def iter_cost_centers(
        self, query: SAPCostCenterQueryModel | None = None
    ) -> SAPODataIterator[SAPCostCenterResponseModel]:
        """Iterate over SAP cost centers - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPCostCenterQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all cost centers).

        Returns:
            SAPODataIterator[SAPCostCenterResponseModel]:
                The iterator over the cost centers.

        """

        return self._iter_odata_collection(
            service="API_COSTCENTER_SRV",
            entity_set="A_CostCenter",
            model=SAPCostCenterResponseModel,
            query=query or SAPCostCenterQueryModel(),
            label="cost centers",
        )

    # end method definition

    def get_cost_centers(self, query: SAPCostCenterQueryModel | None = None) -> list[SAPCostCenterResponseModel] | None:
        """Get SAP cost centers as a list.

        All matching cost centers are read (page by page, see iter_cost_centers()) and returned at once.
        For very large result sets prefer iter_cost_centers().

        Args:
            query (SAPCostCenterQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all cost centers).

        Returns:
            list[SAPCostCenterResponseModel] | None:
                The cost centers (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_cost_centers(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP cost centers.", len(results))

        return results

    # end method definition

    def get_cost_center(
        self, controlling_area: str, cost_center: str, expand_items: bool = True
    ) -> SAPCostCenterResponseModel | None:
        """Get a single SAP cost center (master data).

        Cost center data is time dependent - the currently valid version (latest validity end date) is returned.

        Args:
            controlling_area (str):
                The controlling area, e.g. "A000".
            cost_center (str):
                The cost center, e.g. "0000004130".
            expand_items (bool, optional):
                Whether to read the names as well. Defaults to True.

        Returns:
            SAPCostCenterResponseModel | None:
                The cost center or None if it does not exist or in case of an error.

        """

        # Sorted with the latest validity period first:
        entries = self.iter_cost_centers(
            query=SAPCostCenterQueryModel(
                controlling_area=controlling_area, cost_centers=[cost_center], limit=1, expand_items=expand_items
            ),
        )
        entry = next(entries, None)
        if entry is None and not entries.failed:
            self.logger.warning("Cannot find SAP cost center -> %s/%s", controlling_area, cost_center)

        return entry

    # end method definition

    def iter_profit_centers(
        self, query: SAPProfitCenterQueryModel | None = None
    ) -> SAPODataIterator[SAPProfitCenterResponseModel]:
        """Iterate over SAP profit centers - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPProfitCenterQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all profit centers).

        Returns:
            SAPODataIterator[SAPProfitCenterResponseModel]:
                The iterator over the profit centers.

        """

        return self._iter_odata_collection(
            service="API_PROFITCENTER_SRV",
            entity_set="A_ProfitCenter",
            model=SAPProfitCenterResponseModel,
            query=query or SAPProfitCenterQueryModel(),
            label="profit centers",
        )

    # end method definition

    def get_profit_centers(
        self, query: SAPProfitCenterQueryModel | None = None
    ) -> list[SAPProfitCenterResponseModel] | None:
        """Get SAP profit centers as a list.

        All matching profit centers are read (page by page, see iter_profit_centers()) and returned at once.
        For very large result sets prefer iter_profit_centers().

        Args:
            query (SAPProfitCenterQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all profit centers).

        Returns:
            list[SAPProfitCenterResponseModel] | None:
                The profit centers (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_profit_centers(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP profit centers.", len(results))

        return results

    # end method definition

    def get_profit_center(
        self, controlling_area: str, profit_center: str, expand_items: bool = True
    ) -> SAPProfitCenterResponseModel | None:
        """Get a single SAP profit center (master data).

        Profit center data is time dependent - the currently valid version (latest validity end date) is returned.

        Args:
            controlling_area (str):
                The controlling area, e.g. "A000".
            profit_center (str):
                The profit center, e.g. "YB101".
            expand_items (bool, optional):
                Whether to read the names as well. Defaults to True.

        Returns:
            SAPProfitCenterResponseModel | None:
                The profit center or None if it does not exist or in case of an error.

        """

        # Sorted with the latest validity period first:
        entries = self.iter_profit_centers(
            query=SAPProfitCenterQueryModel(
                controlling_area=controlling_area, profit_centers=[profit_center], limit=1, expand_items=expand_items
            ),
        )
        entry = next(entries, None)
        if entry is None and not entries.failed:
            self.logger.warning("Cannot find SAP profit center -> %s/%s", controlling_area, profit_center)

        return entry

    # end method definition

    def iter_gl_accounts(
        self, query: SAPGLAccountQueryModel | None = None
    ) -> SAPODataIterator[SAPGLAccountResponseModel]:
        """Iterate over SAP G/L accounts - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPGLAccountQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all G/L accounts).

        Returns:
            SAPODataIterator[SAPGLAccountResponseModel]:
                The iterator over the G/L accounts.

        """

        return self._iter_odata_collection(
            service="API_GLACCOUNTINCHARTOFACCOUNTS_SRV",
            entity_set="A_GLAccountInChartOfAccounts",
            model=SAPGLAccountResponseModel,
            query=query or SAPGLAccountQueryModel(),
            label="G/L accounts",
        )

    # end method definition

    def get_gl_accounts(self, query: SAPGLAccountQueryModel | None = None) -> list[SAPGLAccountResponseModel] | None:
        """Get SAP G/L accounts as a list.

        All matching G/L accounts are read (page by page, see iter_gl_accounts()) and returned at once.
        For very large result sets prefer iter_gl_accounts().

        Args:
            query (SAPGLAccountQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all G/L accounts).

        Returns:
            list[SAPGLAccountResponseModel] | None:
                The G/L accounts (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_gl_accounts(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP G/L accounts.", len(results))

        return results

    # end method definition

    def get_gl_account(
        self, chart_of_accounts: str, gl_account: str, expand_items: bool = True
    ) -> SAPGLAccountResponseModel | None:
        """Get a single SAP G/L account (master data).

        Args:
            chart_of_accounts (str):
                The chart of accounts, e.g. "YCOA".
            gl_account (str):
                The G/L account number, e.g. "0000400000".
            expand_items (bool, optional):
                Whether to read the names as well. Defaults to True.

        Returns:
            SAPGLAccountResponseModel | None:
                The G/L account or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_GLACCOUNTINCHARTOFACCOUNTS_SRV",
            entity_path="A_GLAccountInChartOfAccounts(ChartOfAccounts='{}',GLAccount='{}')".format(
                self._quote_key(chart_of_accounts), self._quote_key(gl_account)
            ),
            model=SAPGLAccountResponseModel,
            params={"$expand": "to_Text"} if expand_items else None,
            label="G/L account -> {}/{}".format(chart_of_accounts, gl_account),
        )

    # end method definition

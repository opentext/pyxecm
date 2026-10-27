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
* Inventory Management: API_MATERIAL_DOCUMENT_SRV, API_MATERIAL_STOCK_SRV
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
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from http import HTTPStatus
from importlib.metadata import version
from typing import ClassVar

import requests
from lxml import etree
from opentelemetry import trace
from pydantic import BaseModel, ValidationError
from pyxecm.errors import (
    ErrorCategory,
    PyxecmError,
    ReportingLoggerAttribute,
    record_error,
    request_error_severity,
    warn_parse_error_response_deprecated,
)

from .sap_metadata import ODataEntityType, parse_odata_metadata, to_odata_value
from .sap_models import (
    ODataCondition,
    SAPAuthCheckState,
    SAPAuthCheckStatusModel,
    SAPBillingDocumentItemQueryModel,
    SAPBillingDocumentItemResponseModel,
    SAPBillingDocumentQueryModel,
    SAPBillingDocumentRequestQueryModel,
    SAPBillingDocumentRequestResponseModel,
    SAPBillingDocumentResponseModel,
    SAPBusinessObjectType,
    SAPBusinessPartnerModel,
    SAPBusinessPartnerQueryModel,
    SAPBusinessPartnerResponseModel,
    SAPCompanyCodeQueryModel,
    SAPCompanyCodeResponseModel,
    SAPCostCenterQueryModel,
    SAPCostCenterResponseModel,
    SAPCreditMemoRequestAction,
    SAPCreditMemoRequestItemModel,
    SAPCreditMemoRequestModel,
    SAPCreditMemoRequestQueryModel,
    SAPCreditMemoRequestResponseModel,
    SAPCustomerQueryModel,
    SAPDebitMemoRequestItemModel,
    SAPDebitMemoRequestModel,
    SAPDebitMemoRequestQueryModel,
    SAPDebitMemoRequestResponseModel,
    SAPEquipmentModel,
    SAPEquipmentQueryModel,
    SAPEquipmentResponseModel,
    SAPFunctionalLocationModel,
    SAPFunctionalLocationQueryModel,
    SAPFunctionalLocationResponseModel,
    SAPGLAccountQueryModel,
    SAPGLAccountResponseModel,
    SAPGoodsMovementItemQueryModel,
    SAPGoodsMovementItemResponseModel,
    SAPGoodsMovementModel,
    SAPGoodsMovementQueryModel,
    SAPGoodsMovementResponseModel,
    SAPInboundDeliveryAction,
    SAPInboundDeliveryItemModel,
    SAPInboundDeliveryItemQueryModel,
    SAPInboundDeliveryItemResponseModel,
    SAPInboundDeliveryModel,
    SAPInboundDeliveryQueryModel,
    SAPInboundDeliveryResponseModel,
    SAPMaintenanceNotificationAction,
    SAPMaintenanceNotificationItemModel,
    SAPMaintenanceNotificationModel,
    SAPMaintenanceNotificationQueryModel,
    SAPMaintenanceNotificationResponseModel,
    SAPMaintenanceOrderAction,
    SAPMaintenanceOrderComponentModel,
    SAPMaintenanceOrderConfirmationModel,
    SAPMaintenanceOrderConfirmationQueryModel,
    SAPMaintenanceOrderConfirmationResponseModel,
    SAPMaintenanceOrderModel,
    SAPMaintenanceOrderOperationAction,
    SAPMaintenanceOrderOperationModel,
    SAPMaintenanceOrderQueryModel,
    SAPMaintenanceOrderResponseModel,
    SAPMaintenancePlanAction,
    SAPMaintenancePlanItemModel,
    SAPMaintenancePlanItemQueryModel,
    SAPMaintenancePlanItemResponseModel,
    SAPMaintenancePlanModel,
    SAPMaintenancePlanQueryModel,
    SAPMaintenancePlanResponseModel,
    SAPMaterialBOMItemModel,
    SAPMaterialBOMModel,
    SAPMaterialBOMQueryModel,
    SAPMaterialBOMResponseModel,
    SAPMaterialStockQueryModel,
    SAPMaterialStockResponseModel,
    SAPODataCreateModel,
    SAPODataErrorModel,
    SAPODataModel,
    SAPODataQueryModel,
    SAPODataServiceModel,
    SAPODataServiceState,
    SAPODataServiceStatusModel,
    SAPODataTextQueryModel,
    SAPODataTextResponseModel,
    SAPOutboundDeliveryAction,
    SAPOutboundDeliveryItemModel,
    SAPOutboundDeliveryItemQueryModel,
    SAPOutboundDeliveryItemResponseModel,
    SAPOutboundDeliveryModel,
    SAPOutboundDeliveryQueryModel,
    SAPOutboundDeliveryResponseModel,
    SAPPlannedOrderComponentModel,
    SAPPlannedOrderModel,
    SAPPlannedOrderQueryModel,
    SAPPlannedOrderResponseModel,
    SAPPlantQueryModel,
    SAPPlantResponseModel,
    SAPProductDescriptionModel,
    SAPProductionOrderAction,
    SAPProductionOrderModel,
    SAPProductionOrderOperationModel,
    SAPProductionOrderQueryModel,
    SAPProductionOrderResponseModel,
    SAPProductionVersionQueryModel,
    SAPProductionVersionResponseModel,
    SAPProductModel,
    SAPProductPlantModel,
    SAPProductQueryModel,
    SAPProductResponseModel,
    SAPProductStorageLocationModel,
    SAPProductValuationModel,
    SAPProfitCenterQueryModel,
    SAPProfitCenterResponseModel,
    SAPPurchaseContractItemModel,
    SAPPurchaseContractModel,
    SAPPurchaseContractQueryModel,
    SAPPurchaseContractResponseModel,
    SAPPurchaseOrderItemModel,
    SAPPurchaseOrderModel,
    SAPPurchaseOrderQueryModel,
    SAPPurchaseOrderResponseModel,
    SAPPurchaseRequisitionItemModel,
    SAPPurchaseRequisitionModel,
    SAPPurchaseRequisitionQueryModel,
    SAPPurchaseRequisitionResponseModel,
    SAPPurchasingOrganizationQueryModel,
    SAPPurchasingOrganizationResponseModel,
    SAPSalesContractItemModel,
    SAPSalesContractModel,
    SAPSalesContractQueryModel,
    SAPSalesContractResponseModel,
    SAPSalesOrderItemModel,
    SAPSalesOrderModel,
    SAPSalesOrderQueryModel,
    SAPSalesOrderResponseModel,
    SAPSalesOrganizationQueryModel,
    SAPSalesOrganizationResponseModel,
    SAPStorageLocationQueryModel,
    SAPStorageLocationResponseModel,
    SAPSupplierInvoiceModel,
    SAPSupplierInvoiceQueryModel,
    SAPSupplierInvoiceResponseModel,
    SAPSupplierQueryModel,
    SAPTaskListModel,
    SAPTaskListOperationModel,
    SAPTaskListQueryModel,
    SAPTaskListResponseModel,
    SAPWorkCenterQueryModel,
    SAPWorkCenterResponseModel,
    odata_literal,
    pad_number,
    text_search_variants,
)

default_logger = logging.getLogger("pyxecm_customizer.sap")
tracer = trace.get_tracer(__name__)
OTEL_TRACING_ATTRIBUTES = {"class": "sap"}

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
# new SAP APIs are supported by the SAP class. The OAuth scope IDs are
# generated by SAP and can differ between SAP systems - see get_oauth_scope():
SAP_ODATA_SERVICES: dict[str, SAPODataServiceModel] = {
    "API_MAINTENANCEORDER": SAPODataServiceModel(
        name="API_MAINTENANCEORDER",
        # Version 0002 ("Maintenance Order (Version 2)") is the successor of the
        # deprecated version 0001 - both are identical for the fields we use:
        path="/sap/opu/odata/sap/API_MAINTENANCEORDER;v=0002",
        odata_version=2,
        oauth_scope="ZAPI_MAINTENANCEORDER_0002",
        entity_sets=["MaintenanceOrder", "MaintenanceOrderOperation"],
        description="Plant Maintenance - Maintenance Order (Create, Read, Update, Operations)",
    ),
    # RAP based service, published as OData V2 (service binding API_MAINTNOTIFICATION, version 0001):
    "API_MAINTNOTIFICATION": SAPODataServiceModel(
        name="API_MAINTNOTIFICATION",
        path="/sap/opu/odata/sap/API_MAINTNOTIFICATION",
        odata_version=2,
        oauth_scope="ZAPI_MAINTNOTIFICATION_0001",
        entity_sets=["MaintenanceNotification", "MaintenanceNotificationItem"],
        description="Plant Maintenance - Maintenance Notification (Create, Read, Update)",
    ),
    "API_SALES_ORDER_SRV": SAPODataServiceModel(
        name="API_SALES_ORDER_SRV",
        path="/sap/opu/odata/sap/API_SALES_ORDER_SRV",
        odata_version=2,
        oauth_scope="ZAPI_SALES_ORDER_SRV_0001",
        entity_sets=["A_SalesOrder", "A_SalesOrderItem"],
        description="Sales - Sales Order (Create, Read, Update, Delete)",
    ),
    "API_SALES_CONTRACT_SRV": SAPODataServiceModel(
        name="API_SALES_CONTRACT_SRV",
        path="/sap/opu/odata/sap/API_SALES_CONTRACT_SRV",
        odata_version=2,
        oauth_scope="ZAPI_SALES_CONTRACT_SRV_0001",
        entity_sets=["A_SalesContract", "A_SalesContractItem"],
        description="Sales - Sales Contract (Create, Read, Update, Delete)",
    ),
    "API_CREDIT_MEMO_REQUEST_SRV": SAPODataServiceModel(
        name="API_CREDIT_MEMO_REQUEST_SRV",
        path="/sap/opu/odata/sap/API_CREDIT_MEMO_REQUEST_SRV",
        odata_version=2,
        oauth_scope="ZAPI_CREDIT_MEMO_REQUEST_SRV_0001",
        entity_sets=["A_CreditMemoRequest", "A_CreditMemoRequestItem"],
        description="Sales - Credit Memo Request (Create, Read, Update, Delete, Approval)",
    ),
    "API_DEBIT_MEMO_REQUEST_SRV": SAPODataServiceModel(
        name="API_DEBIT_MEMO_REQUEST_SRV",
        path="/sap/opu/odata/sap/API_DEBIT_MEMO_REQUEST_SRV",
        odata_version=2,
        oauth_scope="ZAPI_DEBIT_MEMO_REQUEST_SRV_0001",
        entity_sets=["A_DebitMemoRequest", "A_DebitMemoRequestItem"],
        description="Sales - Debit Memo Request (Create, Read, Update, Delete)",
    ),
    "API_BILLING_DOCUMENT_REQUEST_SRV": SAPODataServiceModel(
        name="API_BILLING_DOCUMENT_REQUEST_SRV",
        path="/sap/opu/odata/sap/API_BILLING_DOCUMENT_REQUEST_SRV",
        odata_version=2,
        oauth_scope="ZAPI_BILLING_DOCUMENT_REQUEST_SRV_0001",
        entity_sets=["A_BillingDocumentRequest", "A_BillingDocumentRequestItem"],
        description="Billing - Billing Document Request (Read, Delete, Reject)",
    ),
    "API_BILLING_DOCUMENT_SRV": SAPODataServiceModel(
        name="API_BILLING_DOCUMENT_SRV",
        path="/sap/opu/odata/sap/API_BILLING_DOCUMENT_SRV",
        odata_version=2,
        oauth_scope="ZAPI_BILLING_DOCUMENT_SRV_0001",
        entity_sets=["A_BillingDocument", "A_BillingDocumentItem"],
        description="Billing - Billing Document / Customer Invoice (Read, Cancel, PDF)",
    ),
    # Version 0002 is the successor of the deprecated version 0001:
    "API_OUTBOUND_DELIVERY_SRV": SAPODataServiceModel(
        name="API_OUTBOUND_DELIVERY_SRV",
        path="/sap/opu/odata/sap/API_OUTBOUND_DELIVERY_SRV;v=0002",
        odata_version=2,
        oauth_scope="ZAPI_OUTBOUND_DELIVERY_SRV_0002",
        entity_sets=["A_OutbDeliveryHeader", "A_OutbDeliveryItem"],
        description="Shipping - Outbound Delivery (Create, Read, Update, Delete, Picking, Goods Issue)",
    ),
    # Version 0001 matches the published SAP metadata for this API. The system also has
    # version 0002 (";v=0002") - compare both with check_odata_apis() after activation:
    "API_PURCHASECONTRACT_PROCESS_SRV": SAPODataServiceModel(
        name="API_PURCHASECONTRACT_PROCESS_SRV",
        path="/sap/opu/odata/sap/API_PURCHASECONTRACT_PROCESS_SRV",
        odata_version=2,
        oauth_scope="ZAPI_PURCHASECONTRACT_PROCESS_SRV_0001",
        entity_sets=["A_PurchaseContract", "A_PurchaseContractItem"],
        description="Purchasing - Purchase Contract (Create, Read, Update, Delete Items)",
    ),
    # OData V4 successor of the V2 API API_PURCHASEREQ_PROCESS_SRV (service group
    # API_PURCHASEREQUISITION_2, service "PurchaseRequisition", version 0001):
    "API_PURCHASEREQUISITION_2": SAPODataServiceModel(
        name="API_PURCHASEREQUISITION_2",
        path="/sap/opu/odata4/sap/api_purchaserequisition_2/srvd_a2x/sap/purchaserequisition/0001",
        odata_version=4,
        oauth_scope="OV4:API_PURCHASEREQUISITION_2",
        entity_sets=["PurchaseReqn", "PurchaseReqnItem", "PurchaseReqnAcctAssgmt"],
        description="Purchasing - Purchase Requisition (Create, Read, Update)",
    ),
    "API_SUPPLIERINVOICE_PROCESS_SRV": SAPODataServiceModel(
        name="API_SUPPLIERINVOICE_PROCESS_SRV",
        path="/sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV",
        odata_version=2,
        oauth_scope="ZAPI_SUPPLIERINVOICE_PROCESS_SRV_0001",
        entity_sets=["A_SupplierInvoice", "A_SuplrInvcItemPurOrdRef", "A_SupplierInvoiceItemGLAcct"],
        description="Purchasing - Supplier Invoice (Create, Park, Post, Read, Delete, Cancel, Release)",
    ),
    # Version 0002 is the successor of the deprecated version 0001:
    "API_INBOUND_DELIVERY_SRV": SAPODataServiceModel(
        name="API_INBOUND_DELIVERY_SRV",
        path="/sap/opu/odata/sap/API_INBOUND_DELIVERY_SRV;v=0002",
        odata_version=2,
        oauth_scope="ZAPI_INBOUND_DELIVERY_SRV_0002",
        entity_sets=["A_InbDeliveryHeader", "A_InbDeliveryItem"],
        description="Purchasing - Inbound Delivery (Create, Read, Update, Delete, Putaway, Goods Receipt)",
    ),
    "API_MATERIAL_DOCUMENT_SRV": SAPODataServiceModel(
        name="API_MATERIAL_DOCUMENT_SRV",
        path="/sap/opu/odata/sap/API_MATERIAL_DOCUMENT_SRV",
        odata_version=2,
        oauth_scope="ZAPI_MATERIAL_DOCUMENT_SRV_0001",
        entity_sets=["A_MaterialDocumentHeader", "A_MaterialDocumentItem"],
        description="Inventory Management - Goods Movement / Material Document (Create, Read, Cancel)",
    ),
    "API_MATERIAL_STOCK_SRV": SAPODataServiceModel(
        name="API_MATERIAL_STOCK_SRV",
        path="/sap/opu/odata/sap/API_MATERIAL_STOCK_SRV",
        odata_version=2,
        oauth_scope="ZAPI_MATERIAL_STOCK_SRV_0001",
        entity_sets=["A_MaterialStock", "A_MatlStkInAcctMod"],
        description="Inventory Management - Material Stock (Read)",
    ),
    # RAP based services, published as OData V2:
    "API_MAINTORDERCONFIRMATION": SAPODataServiceModel(
        name="API_MAINTORDERCONFIRMATION",
        path="/sap/opu/odata/sap/API_MAINTORDERCONFIRMATION",
        odata_version=2,
        oauth_scope="ZAPI_MAINTORDERCONFIRMATION_0001",
        entity_sets=["MaintOrderConfirmation"],
        description="Plant Maintenance - Maintenance Order Confirmation (Create, Read, Cancel)",
    ),
    "API_MAINTENANCEPLAN": SAPODataServiceModel(
        name="API_MAINTENANCEPLAN",
        path="/sap/opu/odata/sap/API_MAINTENANCEPLAN",
        odata_version=2,
        oauth_scope="ZAPI_MAINTENANCEPLAN_0001",
        entity_sets=["MaintenancePlan", "MaintenancePlanCycle", "MaintenanceItem"],
        description="Plant Maintenance - Maintenance Plan (Create, Read, Update, Scheduling)",
    ),
    # RAP based service (service group API_MAINTENANCETASKLIST, service "MaintenanceTaskList",
    # version 0001). The service group must be published in /IWFND/V4_ADMIN:
    "API_MAINTENANCETASKLIST": SAPODataServiceModel(
        name="API_MAINTENANCETASKLIST",
        path="/sap/opu/odata4/sap/api_maintenancetasklist/srvd_a2x/sap/maintenancetasklist/0001",
        odata_version=4,
        oauth_scope="OV4:API_MAINTENANCETASKLIST",
        entity_sets=["MaintenanceTaskList", "MaintenanceTaskListOperation"],
        description="Plant Maintenance - Maintenance Task List (Create, Read, Update)",
    ),
    # Successor of the V2 API API_PLANNED_ORDERS (service group API_PLANNEDORDER, service
    # "PlannedOrder", version 0001):
    "API_PLANNEDORDER": SAPODataServiceModel(
        name="API_PLANNEDORDER",
        path="/sap/opu/odata4/sap/api_plannedorder/srvd_a2x/sap/plannedorder/0001",
        odata_version=4,
        oauth_scope="OV4:API_PLANNEDORDER",
        entity_sets=["PlannedOrderHeader"],
        description="Production Planning - Planned Order (Create, Read, Update, Delete, Schedule)",
    ),
    "API_PRODUCTION_ORDER_2_SRV": SAPODataServiceModel(
        name="API_PRODUCTION_ORDER_2_SRV",
        path="/sap/opu/odata/sap/API_PRODUCTION_ORDER_2_SRV",
        odata_version=2,
        oauth_scope="ZAPI_PRODUCTION_ORDER_2_SRV_0001",
        entity_sets=["A_ProductionOrder_2", "A_ProductionOrderOperation_2", "A_ProductionOrderStatus_2"],
        description="Production Planning - Production Order (Create, Read, Update, Convert, Status)",
    ),
    # Master data APIs (used read only):
    "API_PLANT_2": SAPODataServiceModel(
        name="API_PLANT_2",
        path="/sap/opu/odata4/sap/api_plant_2/srvd_a2x/sap/plant/0001",
        odata_version=4,
        oauth_scope="OV4:API_PLANT_2",
        entity_sets=["Plant"],
        description="Master Data - Plant (Read)",
    ),
    "API_STORAGELOCATION_SRV": SAPODataServiceModel(
        name="API_STORAGELOCATION_SRV",
        path="/sap/opu/odata/sap/API_STORAGELOCATION_SRV",
        odata_version=2,
        oauth_scope="ZAPI_STORAGELOCATION_SRV_0001",
        entity_sets=["StorageLocation"],
        description="Master Data - Storage Location (Read)",
    ),
    "API_PRODUCT_SRV": SAPODataServiceModel(
        name="API_PRODUCT_SRV",
        path="/sap/opu/odata/sap/API_PRODUCT_SRV",
        odata_version=2,
        oauth_scope="ZAPI_PRODUCT_SRV_0001",
        entity_sets=["A_Product", "A_ProductPlant", "A_ProductDescription"],
        description="Master Data - Product / Material (Create, Read)",
    ),
    # Version 0002 of the material BOM API (the successor of the deprecated version 0001):
    "API_BILL_OF_MATERIAL_SRV": SAPODataServiceModel(
        name="API_BILL_OF_MATERIAL_SRV",
        path="/sap/opu/odata/sap/API_BILL_OF_MATERIAL_SRV;v=0002",
        odata_version=2,
        oauth_scope="ZAPI_BILL_OF_MATERIAL_SRV_0002",
        entity_sets=["MaterialBOM", "MaterialBOMItem"],
        description="Master Data - Material BOM (Create, Read)",
    ),
    "API_PRODUCTION_VERSION": SAPODataServiceModel(
        name="API_PRODUCTION_VERSION",
        path="/sap/opu/odata4/sap/api_production_version/srvd_a2x/sap/productionversion/0001",
        odata_version=4,
        oauth_scope="OV4:API_PRODUCTION_VERSION",
        entity_sets=["ProductionVersion"],
        description="Master Data - Production Version (Read)",
    ),
    "API_WORK_CENTERS": SAPODataServiceModel(
        name="API_WORK_CENTERS",
        path="/sap/opu/odata/sap/API_WORK_CENTERS",
        odata_version=2,
        oauth_scope="ZAPI_WORK_CENTERS_0001",
        entity_sets=["A_WorkCenters"],
        description="Master Data - Work Center (Read)",
    ),
    "API_EQUIPMENT": SAPODataServiceModel(
        name="API_EQUIPMENT",
        path="/sap/opu/odata/sap/API_EQUIPMENT",
        odata_version=2,
        oauth_scope="ZAPI_EQUIPMENT_0001",
        entity_sets=["Equipment"],
        description="Master Data - Equipment (Create, Read)",
    ),
    "API_FUNCTIONALLOCATION": SAPODataServiceModel(
        name="API_FUNCTIONALLOCATION",
        path="/sap/opu/odata/sap/API_FUNCTIONALLOCATION",
        odata_version=2,
        oauth_scope="ZAPI_FUNCTIONALLOCATION_0001",
        entity_sets=["FunctionalLocation"],
        description="Master Data - Functional Location (Create, Read)",
    ),
    "API_BUSINESS_PARTNER": SAPODataServiceModel(
        name="API_BUSINESS_PARTNER",
        path="/sap/opu/odata/sap/API_BUSINESS_PARTNER",
        odata_version=2,
        oauth_scope="ZAPI_BUSINESS_PARTNER_0001",
        entity_sets=["A_BusinessPartner", "A_BusinessPartnerRole"],
        description="Master Data - Business Partner (Read / Create)",
    ),
    "API_COMPANYCODE_SRV": SAPODataServiceModel(
        name="API_COMPANYCODE_SRV",
        path="/sap/opu/odata/sap/API_COMPANYCODE_SRV",
        odata_version=2,
        oauth_scope="ZAPI_COMPANYCODE_SRV_0001",
        entity_sets=["A_CompanyCode"],
        description="Master Data - Company Code (Read)",
    ),
    "API_SALESORGANIZATION_SRV": SAPODataServiceModel(
        name="API_SALESORGANIZATION_SRV",
        path="/sap/opu/odata/sap/API_SALESORGANIZATION_SRV",
        odata_version=2,
        oauth_scope="ZAPI_SALESORGANIZATION_SRV_0001",
        entity_sets=["A_SalesOrganization"],
        description="Master Data - Sales Organization (Read)",
    ),
    "API_PURCHASINGORGANIZATION": SAPODataServiceModel(
        name="API_PURCHASINGORGANIZATION",
        path="/sap/opu/odata4/sap/api_purchasingorganization/srvd_a2x/sap/purchasingorganization/0001",
        odata_version=4,
        oauth_scope="OV4:API_PURCHASINGORGANIZATION",
        entity_sets=["A_PurchasingOrganization"],
        description="Master Data - Purchasing Organization (Read)",
    ),
    "API_COSTCENTER_SRV": SAPODataServiceModel(
        name="API_COSTCENTER_SRV",
        path="/sap/opu/odata/sap/API_COSTCENTER_SRV",
        odata_version=2,
        oauth_scope="ZAPI_COSTCENTER_SRV_0001",
        entity_sets=["A_CostCenter"],
        description="Master Data - Cost Center (Read)",
    ),
    "API_PROFITCENTER_SRV": SAPODataServiceModel(
        name="API_PROFITCENTER_SRV",
        path="/sap/opu/odata/sap/API_PROFITCENTER_SRV",
        odata_version=2,
        oauth_scope="ZAPI_PROFITCENTER_SRV_0001",
        entity_sets=["A_ProfitCenter"],
        description="Master Data - Profit Center (Read)",
    ),
    "API_GLACCOUNTINCHARTOFACCOUNTS_SRV": SAPODataServiceModel(
        name="API_GLACCOUNTINCHARTOFACCOUNTS_SRV",
        path="/sap/opu/odata/sap/API_GLACCOUNTINCHARTOFACCOUNTS_SRV",
        odata_version=2,
        oauth_scope="ZAPI_GLACCOUNTINCHARTOFACCOUNTS_SRV_0001",
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
        oauth_scope="OV4:API_PURCHASEORDER_2",
        entity_sets=[
            "PurchaseOrder",
            "PurchaseOrderItem",
            "PurchaseOrderScheduleLine",
            "PurchaseOrderAccountAssignment",
        ],
        description="Purchasing - Purchase Order (Create, Read, Update, Delete)",
    ),
}


def get_oauth_scope(services: list[str] | None = None) -> str:
    """Build the scope parameter of the OAuth token request from SAP_ODATA_SERVICES.

    Args:
        services (list[str] | None, optional):
            Names of the OData services in SAP_ODATA_SERVICES to get the scopes for.
            Defaults to None (all services in SAP_ODATA_SERVICES).

    Returns:
        str:
            Space-separated scope IDs, e.g. "ZAPI_MAINTENANCEORDER_0002 ZAPI_MAINTNOTIFICATION_0001".
            Services that are not registered or have no scope are skipped.

    """

    if services is None:
        services = list(SAP_ODATA_SERVICES)

    return " ".join(
        SAP_ODATA_SERVICES[service].oauth_scope
        for service in services
        if service in SAP_ODATA_SERVICES and SAP_ODATA_SERVICES[service].oauth_scope
    )


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
# $expand option to read a single business partner with its roles, addresses, supplier and customer data
# (to_Supplier / to_Customer are null if the business partner is no supplier / customer):
BUSINESS_PARTNER_DETAILS_EXPAND = (
    "to_BusinessPartnerRole,"
    "to_BusinessPartnerAddress,"
    "to_Supplier/to_SupplierPurchasingOrg,"
    "to_Supplier/to_SupplierCompany,"
    "to_Customer/to_CustomerSalesArea/to_SalesAreaTax,"
    "to_Customer/to_CustomerSalesArea/to_PartnerFunction,"
    "to_Customer/to_CustomerCompany"
)

# Namespace of the bound actions of the OData V4 planned order API (RAP services use
# "com.sap.gateway.srvd_a2x.<service definition>.v<version>"):
PLANNED_ORDER_ACTION_NAMESPACE = "com.sap.gateway.srvd_a2x.api_plannedorder.v0001"


@dataclass(frozen=True)
class SAPODataItemSet:
    """The items of an SAP document (e.g. the items of a sales order) - how to read them for an update.

    See SAP._update_odata_document(). The items are read with a GET of the collection path. The
    entity path of an item is taken from its __metadata.uri (OData V2) or built from the key
    properties (OData V4) - so internal keys (e.g. of production order operations) work as well.
    """

    # The collection with the items of the document, e.g. "A_SalesOrder('413')/to_Item" or
    # "PlannedOrderComponent" (with a $filter in params):
    collection_path: str
    # The entity set of the items, e.g. "A_SalesOrderItem" (to build the entity path for OData V4):
    entity_set: str
    # The key properties of the items (to build the entity path for OData V4):
    key_properties: tuple[str, ...]
    # The item number users refer to, e.g. "SalesOrderItem" or "ManufacturingOrderOperation":
    number_property: str
    # A text that identifies the item as well, e.g. the item text or the material - items can be
    # referred to by it if it is unique and no item has this number:
    text_property: str | None = None
    # Additional OData query options, e.g. {"$filter": "PlannedOrder eq '103'"}:
    params: dict | None = None
    # Property with the version of an item - if a number occurs several times, the latest version wins:
    version_property: str | None = None
    # The name of an item in messages, e.g. "item", "operation" or "component":
    label: str = "item"


# Messages (in the 'sap-message' header of successful requests) saying that SAP has not changed anything:
SAP_ODATA_NO_CHANGE_MESSAGES = {
    "V1/041": "SAP ignores changes of this field for this document",
}

# Parsed $metadata per (base URL, service) - shared by all SAP objects (e.g. one per user):
_ODATA_METADATA: dict[tuple[str, str], dict[str, ODataEntityType]] = {}
_ODATA_METADATA_LOCK = threading.Lock()


class _ODataReadError(Exception):
    """Internal signal that reading an OData collection failed (the error has been logged already)."""


def _failed_odata_read() -> Iterator:
    """Return the entities of a read that already failed - for a SAPODataIterator with 'failed' set on first use."""

    raise _ODataReadError
    yield  # pragma: no cover - makes this function a generator


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


def parse_bearer_error(response: requests.Response) -> dict[str, str] | None:
    """Parse the OAuth error of an SAP response from its WWW-Authenticate header (RFC 6750).

    With an OAuth access token SAP names the actual problem of a 401 / 403 in this header -
    the body is just a generic HTML error page then, e.g.:
    Bearer realm="...", error="insufficient_scope", error_description="...", scope="ZAPI_SALES_ORDER_SRV_0001"

    Args:
        response (requests.Response):
            The response of SAP.

    Returns:
        dict[str, str] | None:
            The fields of the header (e.g. "error", "error_description", "scope") or None if the
            response has no Bearer error.

    """

    header = response.headers.get("www-authenticate", "")
    if not header.lower().startswith("bearer"):
        return None
    fields = dict(re.findall(r'(\w+)="([^"]*)"', header))

    return fields if fields.get("error") else None


# end function definition


class BearerAuth(requests.auth.AuthBase):
    """Authenticate OData requests with an SAP OAuth 2.0 access token ("Authorization: Bearer").

    Used for principal propagation: pass it as the 'auth' parameter of an SAP object, so
    that all OData calls of this object run as the user the token was issued for.

    Example:
        >>> token = idp_sap.get_oauth_access_token_for_user(user_id="jane.smith@example.com", ...)
        >>> user_sap = SAP(username="", password="", system_id="S4H", base_url=..., auth=BearerAuth(token["access_token"], token["scope"]))

    The token is not renewed - create a new SAP object (with a new token) before it expires
    ('expires_in' of the token response). Each user needs an SAP object of their own, as SAP
    binds its session cookies and CSRF tokens to the user.

    """

    def __init__(self, access_token: str, scope: str | None = None) -> None:
        """Initialize the authentication with an SAP access token.

        Args:
            access_token (str):
                The "access_token" of a token response of get_oauth_access_token().
            scope (str | None, optional):
                The "scope" of the token response - the space-separated scopes SAP granted (the
                requested scopes the OAuth client and the user are authorized for). Defaults to
                None (unknown).

        """

        self._access_token = access_token
        self.scopes: set[str] | None = set(scope.split()) if scope is not None else None

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


# Maximum number of objects found by a text search (name / description) that are read - more
# would make the $filter of the main query too long (see SAP._resolve_text_search()):
TEXT_SEARCH_MAX_IDS = 100


@dataclass(frozen=True)
class SAPError(PyxecmError):
    """An error recorded by the SAP module (SAP class) for pyxecm.capture_errors()."""

    source: ClassVar[str] = "sap"


class SAP:
    """Implement Remote Function Calls (RFC) and OData REST API calls to SAP S/4HANA."""

    # Every assigned logger is wrapped in a ReportingLogger, so that
    # self.logger.error(..., report=True) records the error for capture_errors():
    logger = ReportingLoggerAttribute(default_logger, error_class=SAPError)

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
                report=True,
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
        self.logger.error(text, report=True)
        self._thread_local.last_error = text

    # end method definition

    def oauth_token_url(self) -> str:
        """Return the URL of SAP's OAuth 2.0 token endpoint, including the SAP client.

        SAP checks that the Recipient of a SAML bearer assertion is exactly the URL the
        token request is sent to - including the sap-client query parameter. Both
        get_saml_assertion() and get_oauth_access_token() therefore use this URL.

        Returns:
            str:
                The token endpoint URL, e.g.
                "https://s4.example.com:44300/sap/bc/sec/oauth2/token?sap-client=100".

        """

        return "{}{}?{}".format(self._base_url, OAUTH_TOKEN_PATH, urllib.parse.urlencode({"sap-client": self._client}))

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
                Recipient). Defaults to None = oauth_token_url(), i.e.
                "<base_url>/sap/bc/sec/oauth2/token?sap-client=<client>". Only needed if SAP
                sees the token request under a different URL (e.g. behind a reverse proxy).
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

        recipient = recipient or self.oauth_token_url()
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

        The request is sent as form data to oauth_token_url(). It does
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
                Space-separated scope IDs, e.g. "API_MAINTENANCEORDER_0002 API_MAINTNOTIFICATION_0001" -
                one per OData service that is called with the token. Defaults to None (no scope
                parameter). S/4HANA does not fall back to the scopes of the OAuth client then, but
                answers with "invalid_scope" - pass the scopes explicitly.

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

        # Same URL (incl. sap-client) as the default Recipient of the assertion - SAP compares both:
        token_url = self.oauth_token_url()
        data = {"grant_type": OAUTH_SAML2_BEARER_GRANT_TYPE, "assertion": assertion, "client_id": client_id}
        if scope:
            data["scope"] = scope

        self.logger.debug("Requesting SAP OAuth access token for client -> '%s' from -> %s", client_id, token_url)

        try:
            response = requests.post(
                url=token_url,
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

        # SAP grants the requested scopes that the OAuth client and the user are authorized for and
        # silently drops the others - calls to their services fail later with 403 insufficient_scope:
        missing_scopes = sorted(set((scope or "").split()) - set(token.get("scope", "").split()))
        if missing_scopes and "scope" in token:
            self.logger.warning(
                "SAP did not grant %d of the requested scopes -> %s (missing in S_SCOPE of the user or in the "
                "OAuth client -> '%s') - calls to their OData services will fail with HTTP 403!",
                len(missing_scopes),
                ", ".join(missing_scopes),
                client_id,
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
        recipient: str | None = None,
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
                Space-separated scope IDs, e.g. "API_MAINTENANCEORDER_0002". Defaults to None
                (no scope parameter) - S/4HANA answers with "invalid_scope" then, see
                get_oauth_access_token().
            nameid_format (str, optional):
                The NameID format - must match transaction SAML2 (see get_saml_assertion()).
                Defaults to "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".
            recipient (str | None, optional):
                The Recipient of the assertion - only needed behind a reverse proxy (see
                get_saml_assertion()). Defaults to None = oauth_token_url().

        Returns:
            dict | None:
                The token response (see get_oauth_access_token()) or None if minting the assertion or the token request
                failed (see last_error).

        """

        assertion = self.get_saml_assertion(user_id=user_id, nameid_format=nameid_format, recipient=recipient)
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

    def _service_name_of_url(self, url: str) -> str:
        """Return the name of the OData service of a request URL (for error messages).

        Args:
            url (str):
                The request URL, e.g. ".../sap/opu/odata/sap/API_SALES_ORDER_SRV/A_SalesOrder('413')".

        Returns:
            str:
                The name in SAP_ODATA_SERVICES, e.g. "API_SALES_ORDER_SRV", or the URL path if the
                service is not registered.

        """

        path = url.removeprefix(self._base_url).split("?")[0]
        service = next(
            (
                service
                for service in SAP_ODATA_SERVICES.values()
                if path == service.path or path.startswith(service.path.rstrip("/") + "/")
            ),
            None,
        )

        return service.name if service else path

    # end method definition

    @property
    def granted_scopes(self) -> set[str] | None:
        """Return the OAuth scopes the access token of this SAP object was granted.

        Returns:
            set[str] | None:
                The scopes (see BearerAuth) or None if the object does not use an access token
                or the scopes are unknown.

        """

        return self._auth.scopes if isinstance(self._auth, BearerAuth) else None

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

    def _record_request_error(
        self,
        message: str,
        method: str,
        url: str,
        status_code: int | None = None,
        server_message: str | None = None,
        category: ErrorCategory | None = None,
        show_error: bool = True,
        show_warning: bool = False,
    ) -> None:
        """Record a failed OData request for an active pyxecm.capture_errors() block.

        Unlike the generic pyxecm.errors.record_request_error() this takes the server
        message as it is - SAP's error is parsed (and partly rewritten to actionable hints)
        by do_request() already.

        Args:
            message (str):
                Description of the failed operation (typically the failure message).
            method (str):
                The HTTP method of the request.
            url (str):
                The URL of the request. Query string and fragment are removed.
            status_code (int | None, optional):
                The HTTP status code (if SAP answered).
            server_message (str | None, optional):
                The (readable) error returned by SAP.
            category (ErrorCategory | None, optional):
                The error category. If None, it is determined from status code and server message.
            show_error (bool, optional):
                The show_error parameter of do_request() (determines the severity).
            show_warning (bool, optional):
                The show_warning parameter of do_request() (determines the severity).

        """

        record_error(
            message,
            category=category,
            severity=request_error_severity(show_error=show_error, show_warning=show_warning),
            error_class=SAPError,
            status_code=status_code,
            server_message=server_message,
            method=method,
            url=url,
        )

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
                Deprecated: use capture_errors() to get the error details instead.

        Returns:
            dict | requests.Response | None:
                The parsed response (dict), the response object (if parse_request_response is False),
                or None in case of an error (or the parsed error if parse_error_response is True).

        """

        if parse_error_response:
            warn_parse_error_response_deprecated()

        # Readable error of this request for callers of the public methods (see last_error):
        self._thread_local.last_error = None

        if not self._base_url:
            self.logger.error(
                "Cannot call SAP OData API -> '%s' - the SAP object has been initialized without a base URL!",
                url,
            )
            self._thread_local.last_error = "SAP OData is not configured (no base URL)."
            self._record_request_error(
                message=self._thread_local.last_error, method=method, url=url, category=ErrorCategory.VALIDATION
            )
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
                self._record_request_error(
                    message="{}; request error -> {}".format(failure_message, request_error),
                    method=method,
                    url=url,
                    category=ErrorCategory.CONNECTION,
                )
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
                self._record_request_error(
                    message="{}; SAP is not reachable ({})".format(failure_message, error_text),
                    method=method,
                    url=url,
                    category=ErrorCategory.TIMEOUT if "timeout" in error_text else ErrorCategory.CONNECTION,
                )
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
            bearer_error = parse_bearer_error(response)
            # The authorization errors below are rewritten to readable messages - their
            # category is clear (the text of the messages would not tell it reliably):
            category = None
            if bearer_error and bearer_error["error"] == "insufficient_scope":
                # SAP answers with an HTML page - say which scope is missing and where to add it:
                error.message = (
                    "No authorization for OData service -> '{}': the access token does not contain its scope -> "
                    "'{}'. The scope is missing in the authorizations of the user (S_SCOPE, transaction PFCG) or "
                    "in the OAuth client (transaction SOAUTH2).".format(
                        self._service_name_of_url(url), bearer_error.get("scope", "?")
                    )
                )
                category = ErrorCategory.PERMISSION_DENIED
            elif bearer_error and bearer_error["error"] == "scope_check_impossible":
                category = ErrorCategory.PERMISSION_DENIED
                error.message = (
                    "OAuth is not enabled for OData service -> '{}' (it has no scope) - enable OAuth for it in "
                    "transaction /IWFND/MAINT_SERVICE.".format(self._service_name_of_url(url))
                )
            elif response.status_code == HTTPStatus.FORBIDDEN and error.message == "HTML error page returned":
                category = ErrorCategory.PERMISSION_DENIED
                error.message = (
                    "No authorization for OData service -> '{}' (SAP returned an HTML error page) - check the "
                    "authorizations of the user with transaction SU53, e.g. S_SERVICE.".format(
                        self._service_name_of_url(url)
                    )
                )
            elif response.status_code == HTTPStatus.UNAUTHORIZED:
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
            self._record_request_error(
                message=failure_message if show_error else (warning_message or failure_message),
                method=method,
                url=url,
                status_code=response.status_code,
                server_message=str(error),
                category=category,
                show_error=show_error,
                show_warning=show_warning,
            )

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
            self.logger.error(
                "Cannot check SAP OData APIs - the SAP object has been initialized without a base URL!", report=True
            )
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

        # With an OAuth access token (principal propagation) SAP names the actual problem in the
        # WWW-Authenticate header (RFC 6750) - the body is just a generic HTML error page then:
        bearer_error = parse_bearer_error(response)
        if bearer_error:
            bearer_error_code = bearer_error["error"]
            message = "OAuth error -> {}{}".format(
                bearer_error_code,
                " - {}".format(bearer_error["error_description"]) if bearer_error.get("error_description") else "",
            )
            if bearer_error_code == "scope_check_impossible":
                # SAP finds no scope for the service, i.e. OAuth has not been enabled for it:
                state = SAPODataServiceState.NOT_ACTIVATED
                hint = (
                    "OAuth is not enabled for the service '{}'. Enable OAuth for it in transaction {} (this "
                    "creates its scope ID), assign the scope to the OAuth client in SOAUTH2, authorize the users "
                    "with S_SCOPE in PFCG and add the scope ID to SAP__OAUTH_SCOPE.".format(
                        service.name,
                        activation_transaction,
                    )
                )
            elif bearer_error_code == "insufficient_scope":
                state = SAPODataServiceState.FORBIDDEN
                hint = (
                    "The access token does not carry the scope of the service '{}'. Add its scope ID to "
                    "SAP__OAUTH_SCOPE, assign it to the OAuth client in SOAUTH2 and authorize the users with "
                    "S_SCOPE in PFCG.".format(service.name)
                )
            elif bearer_error_code == "invalid_token":
                state = SAPODataServiceState.UNAUTHORIZED
                hint = (
                    "The access token is invalid or expired. Get a new token (get_oauth_access_token_for_user()) - "
                    "tokens are only valid in the SAP client they were issued for."
                )
            else:
                state = SAPODataServiceState.ERROR
                hint = (
                    "SAP rejected the OAuth access token. See SAP note 1688545 (OAuth 2.0 troubleshooting) and "
                    "the security audit log (SM20)."
                )
            return SAPODataServiceStatusModel(
                service=service,
                url=url,
                state=state,
                http_status=status_code,
                message=message,
                hint=hint,
            )

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

    def check_oauth_token_endpoint(self, timeout: float = REQUEST_TIMEOUT) -> SAPAuthCheckStatusModel:
        """Check if SAP's OAuth 2.0 token endpoint is activated and reachable.

        This is the first step of the SAML 2.0 bearer assertion flow used for principal
        propagation (see get_oauth_access_token()) - before any OAuth client, SAML trust
        or user is involved. An intentionally incomplete token request without client
        credentials and grant_type is sent. A live endpoint answers it with HTTP 401 (the
        ICF node requires the client authentication) or a well-formed OAuth error (e.g.
        "invalid_request"), which is enough to tell apart the typical setup problems:
        * The ICF node /sap/bc/sec/oauth2/token is not active (transaction SICF).
        * The SAP system is not reachable at all (DNS, firewall, TLS, timeout).
        * The base URL points to something else (e.g. a login page of a reverse proxy).

        Args:
            timeout (float, optional):
                Timeout for the check request in seconds. Defaults to REQUEST_TIMEOUT.

        Returns:
            SAPAuthCheckStatusModel:
                The result of the check. Use status.ok to check the result.

        Example:
            >>> status = sap.check_oauth_token_endpoint()
            >>> if not status.ok:
            ...     print(status.hint)

        """

        name = "OAuth 2.0 token endpoint"

        if not self._base_url:
            return SAPAuthCheckStatusModel(
                name=name,
                state=SAPAuthCheckState.NOT_CONFIGURED,
                message="The SAP object has been initialized without a base URL.",
                hint="Set base_url to enable OData / OAuth checks.",
            )

        token_url = self.oauth_token_url()
        self.logger.info("Checking SAP OAuth 2.0 token endpoint at -> %s ...", token_url)

        try:
            response = requests.post(
                url=token_url,
                data={},
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                verify=self._verify_ssl,
                timeout=timeout,
            )
        except requests.exceptions.SSLError as ssl_error:
            status = SAPAuthCheckStatusModel(
                name=name,
                state=SAPAuthCheckState.UNREACHABLE,
                message=str(ssl_error),
                hint="TLS handshake failed. Check the certificate of the SAP system or set verify_ssl=False "
                "for test systems with self-signed certificates.",
            )
        except requests.exceptions.RequestException as request_error:
            status = SAPAuthCheckStatusModel(
                name=name,
                state=SAPAuthCheckState.UNREACHABLE,
                message=str(request_error),
                hint="Check the base URL (protocol, hostname, HTTPS port), DNS resolution and firewall rules.",
            )
        else:
            try:
                body = response.json()
            except ValueError:
                body = {}
            if not isinstance(body, dict):
                body = {}

            if response.status_code == HTTPStatus.NOT_FOUND or (
                response.status_code == HTTPStatus.FORBIDDEN and "service cannot be reached" in response.text.lower()
            ):
                # SAP answers 404 for an unknown path and 403 "Service cannot be reached" for an inactive ICF node:
                status = SAPAuthCheckStatusModel(
                    name=name,
                    state=SAPAuthCheckState.NOT_ACTIVATED,
                    http_status=response.status_code,
                    message="HTTP {} - endpoint not found or not active".format(response.status_code),
                    hint="Activate the ICF node /sap/bc/sec/oauth2/token in transaction SICF.",
                )
            elif response.status_code == HTTPStatus.UNAUTHORIZED:
                # The ICF node authenticates the OAuth client before the OAuth handler runs, so a live
                # endpoint rejects this request without credentials:
                status = SAPAuthCheckStatusModel(
                    name=name,
                    state=SAPAuthCheckState.OK,
                    http_status=response.status_code,
                    message="HTTP 401 - endpoint is active and requires the OAuth client authentication",
                )
            elif "error" in body:
                # Any well-formed OAuth error (e.g. "invalid_request" for the missing grant_type)
                # proves the endpoint itself is live and speaking OAuth 2.0:
                status = SAPAuthCheckStatusModel(
                    name=name,
                    state=SAPAuthCheckState.OK,
                    http_status=response.status_code,
                    message="{} - {}".format(body.get("error"), body.get("error_description", "")),
                )
            else:
                status = SAPAuthCheckStatusModel(
                    name=name,
                    state=SAPAuthCheckState.ERROR,
                    http_status=response.status_code,
                    message="HTTP {} - unexpected response (not a JSON OAuth error)".format(response.status_code),
                    hint="Check that the base URL points to the SAP Gateway and not to a login page or reverse proxy.",
                )

        if status.ok:
            self.logger.info("SAP OAuth 2.0 token endpoint is active; message -> %s", status.message)
        else:
            self.logger.error(
                "SAP OAuth 2.0 token endpoint is not usable; state -> '%s'; message -> %s; hint -> %s",
                status.state.value,
                status.message,
                status.hint,
            )

        return status

    # end method definition

    def check_principal_propagation(
        self,
        user_id: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
        nameid_format: str = SAML_NAMEID_FORMAT_UNSPECIFIED,
        recipient: str | None = None,
    ) -> SAPAuthCheckStatusModel:
        """Check the full SAML 2.0 bearer assertion / OAuth 2.0 principal propagation round trip.

        Runs exactly what get_oauth_access_token_for_user() does for a real user: mint a
        SAML 2.0 assertion for user_id (get_saml_assertion()) and exchange it for an SAP
        access token (get_oauth_access_token()). Use this with a dedicated test user to
        verify the setup end-to-end - unlike check_oauth_token_endpoint() this needs a working OAuth
        client (SOAUTH2), a trusted SAML 2.0 identity provider (SAML2) and a valid NameID
        mapping for user_id. The message of a failed check (SAP's own OAuth error, e.g.
        "invalid_client", "invalid_grant", "unauthorized_client" or "invalid_scope") is kept
        as returned - see the hint for what it typically means.

        Args:
            user_id (str):
                The user to propagate, e.g. a dedicated technical test user. See
                get_saml_assertion() for the security implications.
            client_id (str):
                The OAuth 2.0 client ID registered in SOAUTH2.
            client_secret (str):
                The password of the SU01 system user behind that OAuth client.
            scope (str | None, optional):
                Space-separated scope IDs to request, e.g. "API_MAINTENANCEORDER_0002".
                Defaults to None (no scope parameter) - S/4HANA answers with "invalid_scope"
                then, see get_oauth_access_token().
            nameid_format (str, optional):
                The NameID format - must match transaction SAML2. Defaults to
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".
            recipient (str | None, optional):
                The Recipient of the assertion - only needed behind a reverse proxy (see
                get_saml_assertion()). Defaults to None = oauth_token_url().

        Returns:
            SAPAuthCheckStatusModel:
                The result of the check. Use status.ok to check the result.

        Example:
            >>> status = sap.check_principal_propagation(user_id="jane.smith", client_id="PYXECM_OAUTH", client_secret="...")
            >>> if not status.ok:
            ...     print(status.message, "-", status.hint)

        """

        name = "SAML 2.0 / OAuth 2.0 principal propagation"

        if not self._base_url:
            return SAPAuthCheckStatusModel(
                name=name,
                state=SAPAuthCheckState.NOT_CONFIGURED,
                message="The SAP object has been initialized without a base URL.",
                hint="Set base_url to enable OData / OAuth checks.",
            )

        # Same two steps as get_oauth_access_token_for_user() - separately, so a problem of
        # pyxecm's own identity provider configuration is not mistaken for an SAP-side error:
        assertion = self.get_saml_assertion(user_id=user_id, nameid_format=nameid_format, recipient=recipient)
        if not assertion:
            status = SAPAuthCheckStatusModel(
                name=name,
                state=SAPAuthCheckState.NOT_CONFIGURED
                if self._saml_idp_private_key is None
                else SAPAuthCheckState.ERROR,
                message=self.last_error or "unknown error",
                hint="Check saml_idp_private_key, saml_idp_certificate, saml_issuer and saml_audience of the SAP "
                "object and the user_id - no request has been sent to SAP.",
            )
            self.logger.error(
                "%s failed; state -> '%s'; message -> %s; hint -> %s",
                name,
                status.state.value,
                status.message,
                status.hint,
            )
            return status

        token = self.get_oauth_access_token(
            assertion=assertion, client_id=client_id, client_secret=client_secret, scope=scope
        )
        if token:
            status = SAPAuthCheckStatusModel(
                name=name,
                state=SAPAuthCheckState.OK,
                message="Received access token for user -> '{}' (scope -> '{}', expires in -> {}s)".format(
                    user_id,
                    token.get("scope", ""),
                    token.get("expires_in", "?"),
                ),
            )
            self.logger.info("%s succeeded; message -> %s", name, status.message)
            return status

        error = self.last_error or "unknown error"
        error_lower = error.lower()
        # Wrong client credentials fail the logon of the ICF node already - SAP then answers
        # HTTP 401 without an OAuth error (see get_oauth_access_token() for the format):
        if "invalid_client" in error_lower or "status -> 401/" in error_lower:
            state, hint = (
                SAPAuthCheckState.REJECTED,
                (
                    "Check client_id/client_secret - they must match an SU01 system user with grant type "
                    "'SAML 2.0 Bearer Assertion' configured in transaction SOAUTH2."
                ),
            )
        elif "invalid_grant" in error_lower:
            state, hint = (
                SAPAuthCheckState.REJECTED,
                (
                    "SAP rejected the SAML assertion. Check the trusted identity provider (signing certificate, "
                    "issuer, audience) in transaction SAML2 and that user_id resolves to an SAP user (NameID mapping)."
                ),
            )
        elif "unauthorized_client" in error_lower:
            state, hint = (
                SAPAuthCheckState.REJECTED,
                (
                    "The OAuth client is not authorized for the 'SAML 2.0 Bearer Assertion' grant type - enable it "
                    "in transaction SOAUTH2."
                ),
            )
        elif "invalid_scope" in error_lower and not scope:
            state, hint = (
                SAPAuthCheckState.REJECTED,
                (
                    "No scope was requested - SAP does not fall back to the scopes of the OAuth client. Pass the "
                    "scope IDs of the OData services (setting SAP__OAUTH_SCOPE)."
                ),
            )
        elif "invalid_scope" in error_lower:
            state, hint = (
                SAPAuthCheckState.REJECTED,
                (
                    "The scope is not assigned to the OAuth client or the user is not authorized for it. Enable "
                    "OAuth for the OData service(s) in /IWFND/MAINT_SERVICE and assign the scope(s) to the client "
                    "in SOAUTH2 - and give the user authorization object S_SCOPE for client and scope(s) in PFCG "
                    "(check with SU53). If it works for one user but not another, it is S_SCOPE."
                ),
            )
        else:
            state, hint = (
                SAPAuthCheckState.ERROR,
                "Check the SAP Gateway error log (transaction /IWFND/ERROR_LOG) and the system log (SM21).",
            )

        status = SAPAuthCheckStatusModel(name=name, state=state, message=error, hint=hint)
        self.logger.error(
            "%s failed; state -> '%s'; message -> %s; hint -> %s", name, status.state.value, status.message, status.hint
        )

        return status

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

    def _call_odata_function(
        self,
        service: str,
        function: str,
        parameters: dict,
        label: str,
        etag_entity_path: str | None = None,
        etag: str | None = None,
    ) -> dict | None:
        """Call a function import (action) of an OData V2 service.

        SAP implements actions in OData V2 services (e.g. "ReleaseOrder") as function
        imports that are called with POST and their parameters in the query string.
        Some services require the current ETag of the entity the function changes (If-Match
        header) - SAP answers "428 Precondition required" without it, also for services
        without an ETag property in their $metadata (e.g. RAP based ones). "*" is not accepted.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            function (str):
                The name of the function import, e.g. "ReleaseOrder".
            parameters (dict):
                The parameters of the function import (None values are omitted).
            label (str):
                Describes the call for log messages, e.g. "release production order -> '1000123'".
            etag_entity_path (str | None, optional):
                The path of the entity the function changes, relative to the service root, e.g.
                "A_ProductionOrder_2('1000123')". If given, the entity is read first and its ETag is
                sent in the If-Match header. Defaults to None (no If-Match header).
            etag (str | None, optional):
                The ETag for the If-Match header if the caller knows it already (e.g. the entity
                cannot be read in this service). Defaults to None.

        Returns:
            dict | None:
                The result of the function import (OData V2 "d" unwrapped) or None in case of an error.

        """

        url = self.service_url(service) + "/" + function
        params = {name: odata_literal(value) for name, value in parameters.items() if value is not None}

        headers = {"If-Match": etag} if etag else {}
        if etag_entity_path and not etag:
            exists, etag = self._get_odata_etag(
                url=self.service_url(service) + "/" + etag_entity_path, headers=headers, label=label
            )
            if not exists:
                return None
            headers["If-Match"] = etag or "*"

        self.logger.info("Call SAP function -> '%s' to %s...", function, label)
        response = self.do_request(
            url=url,
            method="POST",
            headers=headers,
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

        The entity is read first and its ETag is sent in the If-Match header - SAP's V4 services
        declare optimistic concurrency (Core.OptimisticConcurrency) and answer "428 Precondition
        required" without it.

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

        headers = dict(ODATA_V4_IEEE754_HEADERS)
        exists, etag = self._get_odata_etag(
            url="{}/{}".format(self.service_url(service), entity_path), headers=dict(headers), label=label
        )
        if not exists:
            return None
        headers["If-Match"] = etag or "*"

        self.logger.info("Call SAP action -> '%s' to %s...", action, label)

        return self.do_request(
            url=url,
            method="POST",
            headers=headers,
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

    def _resolve_text_search[Q: SAPODataQueryModel](self, service: str, query: Q, label: str) -> tuple[Q | None, bool]:
        """Resolve the name / description criterion of a query via the text entity set (see ODataTextSearch).

        The texts are searched (in all languages, case-insensitively via the common spellings of the
        term, see text_search_variants()) and the query is restricted to the IDs of the objects found.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            query (Q):
                The query - unchanged if it has no text search or no search term.
            label (str):
                The (plural) name of the objects for log messages, e.g. "products".

        Returns:
            tuple[Q | None, bool]:
                The query restricted to the IDs found (None if no object matches) and whether reading
                the texts failed.

        """

        search = type(query).TEXT_SEARCH
        term = getattr(query, search.field, None) if search else None
        if not search or not term:
            return query, False

        odata_version = SAP_ODATA_SERVICES[service].odata_version
        variants = text_search_variants(term)
        conditions = [
            " or ".join(
                ODataCondition(text_property, operator="contains").to_filter(
                    value=variants, odata_version=odata_version
                )
                for text_property in search.properties
            )
        ]
        for field_name, text_property in search.scope:
            value = getattr(query, field_name, None)
            if value:
                conditions.append(ODataCondition(text_property).to_filter(value=value, odata_version=odata_version))

        texts = self._iter_odata_collection(
            service=service,
            entity_set=search.entity_set,
            model=SAPODataTextResponseModel,
            query=SAPODataTextQueryModel(conditions=conditions, order_by="{} asc".format(search.key)),
            label="{} texts".format(label),
        )
        ids = list(dict.fromkeys(str((text.model_extra or {}).get(search.key, "")) for text in texts))
        if texts.failed:
            return None, True
        ids = [object_id for object_id in ids if object_id]
        # Combined with IDs given in the query, only the objects of both match:
        given_ids = getattr(query, search.ids_field, None)
        if given_ids:
            ids = [object_id for object_id in ids if object_id in given_ids]
        if not ids:
            self.logger.info("No SAP %s with a name containing -> '%s'.", label, term)
            return None, False
        if len(ids) > TEXT_SEARCH_MAX_IDS:
            self.logger.warning(
                "%d SAP %s have a name containing -> '%s' - only the first %d are read.",
                len(ids),
                label,
                term,
                TEXT_SEARCH_MAX_IDS,
            )
            ids = ids[:TEXT_SEARCH_MAX_IDS]

        return query.model_copy(update={search.ids_field: ids, search.field: None}), False

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

    def get_odata_entity_type(self, service: str, entity_set: str) -> ODataEntityType | None:
        """Return the entity type of an entity set as defined in the $metadata of the service.

        The $metadata is read once per SAP system and service (and kept for all SAP objects).
        A failed read is not kept - the next call tries again.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            entity_set (str):
                The entity set, e.g. "A_SalesOrderItem".

        Returns:
            ODataEntityType | None:
                The entity type or None if the $metadata cannot be read or has no such entity set.

        """

        key = (self._base_url or "", service)
        with _ODATA_METADATA_LOCK:
            entity_types = _ODATA_METADATA.get(key)
        if entity_types is None:
            response = self.do_request(
                url=self.service_url(service) + "/$metadata",
                headers={"Accept": "application/xml"},
                show_error=False,
                show_warning=True,
                warning_message="Cannot read the $metadata of SAP OData service -> '{}'".format(service),
                parse_request_response=False,
            )
            if response is None:
                return None
            try:
                entity_types = parse_odata_metadata(response.content, SAP_ODATA_SERVICES[service].odata_version)
            except (ValueError, TypeError, AttributeError) as error:
                self.logger.warning(
                    "Cannot interpret the $metadata of SAP OData service -> '%s'; error -> %s", service, error
                )
                return None
            with _ODATA_METADATA_LOCK:
                _ODATA_METADATA[key] = entity_types

        return entity_types.get(entity_set)

    # end method definition

    def _prepare_odata_changes(self, service: str, entity_path: str, payload: dict) -> tuple[dict, list[str]]:
        """Check and convert the changes of an entity with the property definitions of the $metadata.

        SAP checks the JSON format of the values strictly (see sap_metadata) - e.g. decimals are
        strings in OData V2 and in OData V4 with IEEE754Compatible=true. Properties that do not
        exist or cannot be changed are rejected (SAP would ignore them or fail with an unclear error).
        If the $metadata cannot be read, the payload is returned unchanged.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            entity_path (str):
                The path of the entity, e.g. "A_SalesOrderItem(SalesOrder='413',SalesOrderItem='10')",
                or just the entity set, e.g. "A_SalesOrderItem".
            payload (dict):
                The changes with OData property names (see SAPODataCreateModel.to_odata_update()).

        Returns:
            tuple[dict, list[str]]:
                The converted payload and the unit / currency properties (OData V4) that SAP needs
                together with the changed quantities / amounts but that are not part of the changes.

        Raises:
            ValueError:
                If a property does not exist, cannot be changed or has an invalid value.

        """

        entity_set = entity_path.split("(", 1)[0]
        entity_type = self.get_odata_entity_type(service=service, entity_set=entity_set)
        if entity_type is None:
            return payload, []

        odata_version = SAP_ODATA_SERVICES[service].odata_version
        result = {}
        units = []
        for name, value in payload.items():
            prop = entity_type.properties.get(name)
            if prop is None:
                message = "Unknown property -> '{}' of SAP entity -> '{}'".format(name, entity_set)
                raise ValueError(message)
            if not prop.updatable:
                message = "Property -> '{}' of SAP entity -> '{}' cannot be changed ({})".format(
                    name, entity_set, "key" if prop.is_key else "read-only in SAP"
                )
                raise ValueError(message)
            result[name] = to_odata_value(prop, value, odata_version)
            unit = prop.unit_property
            if not unit:
                continue
            # SAP requires the ISO code of the unit if the entity has one (e.g. "BaseUnitISOCode" for
            # "BaseUnit" - "[/IWBEP/CM_V4_COS/060] ISO unit must be provided"):
            iso_unit = unit + "ISOCode"
            if iso_unit in entity_type.properties:
                unit = iso_unit
            if unit not in payload and prop.unit_property not in payload and unit not in units:
                units.append(unit)

        return result, units

    # end method definition

    def _odata_no_change_message(self, response: requests.Response) -> str | None:
        """Return the message of SAP's 'sap-message' header that says that nothing has been changed.

        Args:
            response (requests.Response):
                The response of a modifying request.

        Returns:
            str | None:
                The message, e.g. "V1/041 No data was changed", or None if SAP reports no such message.

        """

        header = getattr(response, "headers", {}).get("sap-message")
        if not header:
            return None
        try:
            message = json.loads(header)
        except ValueError:
            return None
        # The update has been done - an unexpected header format must not turn it into an error:
        if not isinstance(message, dict):
            return None
        details = message.get("details")
        entries = [message, *(details if isinstance(details, list) else [])]
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("code"), str):
                code = entry["code"]
                if code in SAP_ODATA_NO_CHANGE_MESSAGES:
                    return "{} {}".format(code, entry.get("message") or "").strip()

        return None

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
            payload, units = self._prepare_odata_changes(
                service=service, entity_path=entity_path, payload=model.to_odata_update(changes)
            )
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
        if units:
            # OData V4 quantities / amounts need their unit / currency - send the current one along:
            current = self.do_request(
                url=url,
                params={"$select": ",".join(units)},
                headers=dict(ODATA_V4_IEEE754_HEADERS),
                failure_message="Cannot read the units of SAP {}".format(label),
            )
            if current is None:
                return False
            payload.update({unit: current.get(unit) for unit in units})
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
            parse_request_response=False,
        )
        if response is None:
            return False

        # Some services accept changes of fields they ignore and only report it in the 'sap-message'
        # header, e.g. V1/041 "No data was changed" (HTTP 204) - the update did not happen:
        unchanged = self._odata_no_change_message(response)
        if unchanged:
            self.log_error(
                "SAP did not change %s -> %s (%s) - the changed field(s) cannot be changed this way: %s",
                label,
                unchanged,
                SAP_ODATA_NO_CHANGE_MESSAGES[unchanged.split(" ", 1)[0]],
                ", ".join(payload),
            )
            return False

        return True

    # end method definition

    def _get_odata_items(self, service: str, items: SAPODataItemSet, label: str) -> dict[str, tuple[str, str]] | None:
        """Read the items of an SAP document and return their entity paths (see _update_odata_document()).

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            items (SAPODataItemSet):
                The items of the document.
            label (str):
                The name of the document for log messages, e.g. "sales order -> '413'".

        Returns:
            dict[str, tuple[str, str]] | None:
                {item number without leading zeros: (entity path, item text)} or None in case of an error.

        """

        is_odata_v4 = SAP_ODATA_SERVICES[service].odata_version == 4
        properties = {items.number_property, *items.key_properties}
        if items.text_property:
            properties.add(items.text_property)
        if items.version_property:
            properties.add(items.version_property)
        response = self.do_request(
            url=self.service_url(service) + "/" + items.collection_path,
            params={**(items.params or {}), "$select": ",".join(sorted(properties))},
            headers=ODATA_V4_IEEE754_HEADERS if is_odata_v4 else None,
            show_error=False,
            show_warning=True,
            warning_message="Cannot get the {}s of SAP {}".format(items.label, label),
        )
        if response is None:
            self.log_error("Cannot read the %ss of SAP %s!", items.label, label)
            return None

        entries = response.get("value", []) if is_odata_v4 else response.get("d", {}).get("results", [])
        result: dict[str, tuple[str, str]] = {}
        versions: dict[str, int] = {}
        for entry in entries:
            number = str(entry.get(items.number_property) or "").lstrip("0") or "0"
            version = int(entry.get(items.version_property) or 0) if items.version_property else 0
            if number in versions and versions[number] > version:
                continue
            uri = (entry.get("__metadata") or {}).get("uri", "")
            if uri and not is_odata_v4:
                entity_path = uri.rsplit("/", 1)[-1]
            else:
                entity_path = "{}({})".format(
                    items.entity_set,
                    ",".join(
                        "{}='{}'".format(key, self._quote_key(str(entry.get(key) or "")))
                        for key in items.key_properties
                    ),
                )
            versions[number] = version
            text = str(entry.get(items.text_property) or "") if items.text_property else ""
            result[number] = (entity_path, text)

        return result

    # end method definition

    def _update_odata_document(
        self,
        service: str,
        label: str,
        header_path: str | None,
        header_model: type[SAPODataCreateModel],
        changes: dict | None,
        item_changes: dict[str, dict] | None,
        items: SAPODataItemSet | None,
        item_model: type[SAPODataCreateModel] = SAPODataCreateModel,
    ) -> bool:
        """Update individual fields of an SAP document (header) and of its items.

        All changes are validated first (with the field definitions of the create models) and the
        items must belong to the document - otherwise nothing is changed. Header and items are
        separate entities in SAP (one request each): if a request fails, the changes before it
        remain. The items are changed first and the header last - some documents reject header
        changes in some S/4HANA releases while item changes work (e.g. purchase contracts), so a
        rejected header change does not block the item changes.

        Args:
            service (str):
                The name of the OData service in SAP_ODATA_SERVICES.
            label (str):
                The name of the document for log messages, e.g. "sales order -> '413'".
            header_path (str | None):
                The entity path of the header, e.g. "A_SalesOrder('413')". Only needed for header changes.
            header_model (type[SAPODataCreateModel]):
                The create model whose field definitions are used for the header changes.
            changes (dict | None):
                The header fields to change (snake case attribute names or OData property names).
            item_changes (dict[str, dict] | None):
                The changes per item number (with or without leading zeros), e.g. {"10": {"RequestedQuantity": 5}}.
                An item can also be referred to by its text (see SAPODataItemSet.text_property) if it is unique.
            items (SAPODataItemSet | None):
                The items of the document. Only needed for item changes.
            item_model (type[SAPODataCreateModel], optional):
                The create model whose field definitions are used for the item changes. Defaults to
                SAPODataCreateModel (no field definitions - OData property names only).

        Returns:
            bool:
                True if the document (and its items) have been updated, False in case of an error.

        """

        if not changes and not item_changes:
            self.log_error("No changes given for SAP %s!", label)
            return False
        if item_changes and items is None:
            self.log_error("The items of SAP %s cannot be changed!", label)
            return False

        # Check all changes first - an invalid change must not leave the document half changed:
        try:
            if changes:
                header_payload = header_model.to_odata_update(changes)
                if header_path:
                    self._prepare_odata_changes(service=service, entity_path=header_path, payload=header_payload)
            for item_change in (item_changes or {}).values():
                item_payload = item_model.to_odata_update(item_change)
                if items is not None:
                    self._prepare_odata_changes(service=service, entity_path=items.entity_set, payload=item_payload)
        except ValueError as value_error:
            self.log_error("Invalid changes for SAP %s; error -> %s", label, str(value_error))
            return False

        item_paths: list[tuple[str, str, dict]] = []
        if item_changes and items is not None:
            existing = self._get_odata_items(service=service, items=items, label=label)
            if existing is None:
                return False
            by_text: dict[str, list[str]] = {}
            for number, (_path, text) in existing.items():
                by_text.setdefault(text.casefold(), []).append(number)
            unknown = []
            for item, item_change in item_changes.items():
                number = str(item).strip().lstrip("0") or "0"
                if number not in existing and len(by_text.get(str(item).strip().casefold(), [])) == 1:
                    number = by_text[str(item).strip().casefold()][0]
                if number not in existing:
                    unknown.append(str(item))
                    continue
                item_paths.append((number, existing[number][0], item_change))
            if unknown:
                # List the items - the agent can pick the right one without reading the document again:
                self.log_error(
                    "SAP %s has no %s(s) -> %s! Its %ss are -> %s",
                    label,
                    items.label,
                    ", ".join(unknown),
                    items.label,
                    "; ".join(
                        "{} '{}'".format(number, text) if text else number for number, (_path, text) in existing.items()
                    )
                    or "none",
                )
                return False

        # Stop at the first error - a later successful request would reset last_error:
        for number, entity_path, item_change in item_paths:
            if not self._update_odata_entity(
                service=service,
                entity_path=entity_path,
                model=item_model,
                changes=item_change,
                label="{} -> '{}' of {}".format(items.label if items else "item", number, label),
            ):
                return False

        if not changes:
            return True
        if header_path is None:
            self.log_error("The header of SAP %s cannot be changed!", label)
            return False

        return self._update_odata_entity(
            service=service, entity_path=header_path, model=header_model, changes=changes, label=label
        )

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
        """Create an SAP Plant Maintenance order (including its operations and their components).

        Uses the OData V2 API API_MAINTENANCEORDER: the order header and all operations are
        created (and committed) in one request (deep insert). SAP rejects components in this
        request ("Error reading the order  in the document tables") - they are created for
        the new order afterwards (see create_maintenance_order_component()).

        With a task list reference (SAPMaintenanceOrderModel.task_list), the operations and
        materials of the task list become the first operations and components of the order
        (see expand_maintenance_order_task_list()) - the API cannot include a task list.

        Args:
            order (SAPMaintenanceOrderModel | dict):
                The order data. A dictionary is validated against the SAPMaintenanceOrderModel
                model and can use either the snake case attribute names or the OData
                property names (e.g. "order_type" or "MaintenanceOrderType").

        Returns:
            dict | None:
                The created order as returned by SAP (including "MaintenanceOrder") or None in
                case of an error. If the order has been created but components could not be
                created, the result has the key "ComponentErrors" with the error messages (and
                last_error is set).

        Example:
            >>> sap.create_maintenance_order(
            ... {
            ...     "order_type": "YA01",
            ...     "description": "Replace pump seal",
            ...     "planning_plant": "1010",
            ...     "main_work_center": "RES-0100",
            ...     "main_work_center_plant": "1010",
            ...     "equipment": "210100001",
            ...     "operations": [{"operation": "10", "description": "Replace seal", "control_key": "YBM1"}],
            ...     "task_list": {"task_list_type": "A", "task_list_group": "17", "storage_location": "0001"},
            ... }
            ... )

        """

        if isinstance(order, dict):
            try:
                order = SAPMaintenanceOrderModel.model_validate(order)
            except ValidationError as validation_error:
                self.log_error("Invalid maintenance order data; error -> %s", str(validation_error))
                return None
        if order.task_list:
            order = self.expand_maintenance_order_task_list(order)
            if order is None:
                return None

        created = self._create_odata_entity(
            service="API_MAINTENANCEORDER",
            entity_set="MaintenanceOrder",
            model=SAPMaintenanceOrderModel,
            data=order,
            key_fields=["MaintenanceOrder"],
            label="maintenance order",
        )
        if created is None:
            return None

        # The components need the new order - SAP rejects them in the deep insert:
        component_errors = []
        for operation in order.operations:
            for component in operation.components:
                # The plant of the operation is the default plant of its components:
                if (
                    self.create_maintenance_order_component(
                        order_id=created["MaintenanceOrder"],
                        operation=operation.operation,
                        component=component.model_copy(update={"plant": component.plant or operation.plant}),
                    )
                    is None
                ):
                    component_errors.append(  # noqa: PERF401 - the loop creates the components in SAP
                        "material -> '{}' of operation -> {}: {}".format(
                            component.material, operation.operation, self.last_error
                        )
                    )
        if component_errors:
            self.log_error(
                "Maintenance order -> %s has been created, but %d component(s) could not be created -> %s",
                created["MaintenanceOrder"],
                len(component_errors),
                "; ".join(component_errors),
            )
            created["ComponentErrors"] = component_errors

        return created

    # end method definition

    def expand_maintenance_order_task_list(self, order: SAPMaintenanceOrderModel) -> SAPMaintenanceOrderModel | None:
        """Take over the operations and materials of the task list referenced by a new maintenance order.

        The operations of the task list (number, text, control key, work center, work and
        number of people) become the first operations of the order, their materials the
        components of these operations. Operations of the order itself follow - their
        numbers must not clash with the ones of the task list.

        Args:
            order (SAPMaintenanceOrderModel):
                The order with a task list reference (SAPMaintenanceOrderModel.task_list).

        Returns:
            SAPMaintenanceOrderModel | None:
                A copy of the order with the operations of the task list (and without the task
                list reference) or None in case of an error (e.g. the task list does not exist).

        """

        reference = order.task_list
        if reference is None:
            return order

        task_list = self.get_task_list(
            task_list_type=reference.task_list_type,
            task_list_group=reference.task_list_group,
            task_list_group_counter=reference.task_list_group_counter,
            expand_items=True,
        )
        if task_list is None:
            self.log_error(
                "Cannot take over the operations of task list -> %s/%s/%s into the maintenance order; error -> %s",
                reference.task_list_type,
                reference.task_list_group,
                reference.task_list_group_counter,
                self.last_error,
            )
            return None

        try:
            operations = [
                SAPMaintenanceOrderOperationModel(
                    operation=operation.operation,
                    description=operation.description,
                    control_key=operation.control_key or None,
                    work_center=operation.work_center or None,
                    plant=operation.plant or None,
                    planned_work=operation.work or None,
                    planned_work_unit=operation.work_unit or None,
                    number_of_capacities=operation.number_of_capacities or None,
                    components=[
                        SAPMaintenanceOrderComponentModel(
                            material=material.material,
                            quantity=material.quantity,
                            unit=material.unit,
                            plant=operation.plant or order.planning_plant,
                            storage_location=reference.storage_location,
                            item_category=material.item_category or "L",
                        )
                        for material in operation.materials or []
                    ],
                )
                for operation in sorted(task_list.operations or [], key=lambda item: int(item.operation or 0))
            ]
            expanded = SAPMaintenanceOrderModel.model_validate(
                {
                    **order.model_dump(exclude={"operations", "task_list"}),
                    "operations": [*operations, *order.operations],
                }
            )
        except ValidationError as validation_error:
            self.log_error(
                "Cannot take over the operations of task list -> %s/%s/%s into the maintenance order; error -> %s",
                reference.task_list_type,
                reference.task_list_group,
                reference.task_list_group_counter,
                str(validation_error),
            )
            return None

        return expanded

    # end method definition

    def create_maintenance_order_component(
        self,
        order_id: str,
        operation: str,
        component: SAPMaintenanceOrderComponentModel | dict,
        sub_operation: str = "",
    ) -> dict | None:
        """Create a component (material) for an operation of an existing SAP maintenance order.

        SAP reserves the material (stock item) for the operation.

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            operation (str):
                The operation number, e.g. "0010".
            component (SAPMaintenanceOrderComponentModel | dict):
                The component (material, quantity, unit, plant, storage location, item category).
            sub_operation (str, optional):
                The sub-operation number. Defaults to "" (the operation itself).

        Returns:
            dict | None:
                The created component as returned by SAP (including "Reservation") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_MAINTENANCEORDER",
            entity_set="MaintenanceOrderOperation(MaintenanceOrder='{}',MaintenanceOrderOperation='{}',"
            "MaintenanceOrderSubOperation='{}')/to_MaintOrderOpComponent_2".format(
                self._quote_key(order_id), self._quote_key(operation.zfill(4)), self._quote_key(sub_operation)
            ),
            model=SAPMaintenanceOrderComponentModel,
            data=component,
            key_fields=["MaintOrderComponentInternalID"],
            label="component of operation -> {} of maintenance order -> {}".format(operation, order_id),
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_business_object")
    def get_business_object(self, bo_type: str, bo_id: str) -> SAPODataModel | None:
        """Get an SAP object by the business object reference used by an Extended ECM workspace.

        Dispatch to the corresponding OData getter and return its response model unchanged.
        SAPBusinessObjectType.get_key_fields() converts the internal SAP ID into the
        individual keys, including composite keys such as material document number and year.
        Supported types are listed in SAP_BUSINESS_OBJECT_TYPES in sap_models.py.

        Args:
            bo_type (str):
                The SAP BOR object type, e.g. "BUS2007" or "BUS2017".
            bo_id (str):
                The business object ID in SAP's internal format, e.g. "000004000340"
                or "49000001232026". Single-field IDs also accept the external format.

        Returns:
            SAPODataModel | None:
                The getter's typed SAP object, or None if it does not exist, the type
                is unsupported, the ID is invalid, or the request fails. Use last_error
                or pyxecm.capture_errors() to inspect failures; None alone does not
                prove that the object is absent.

        """

        if not bo_id.strip():
            self.log_error("Cannot get SAP business object of type -> '%s': the ID is empty.", bo_type)
            return None

        try:
            keys = SAPBusinessObjectType.get(bo_type).get_key_fields(bo_id)
        except ValueError as error:
            self.log_error("Cannot get SAP business object: %s", error)
            return None

        if not all(keys):
            self.log_error(
                "Cannot get SAP business object of type -> '%s' with ID -> '%s': a key field is empty.",
                bo_type,
                bo_id,
            )
            return None

        self.logger.debug("Get SAP business object of type -> '%s' with ID -> '%s'", bo_type, bo_id)

        match bo_type:
            case "BUS2007":
                return self.get_maintenance_order(order_id=keys[0])
            case "BUS2038":
                return self.get_maintenance_notification(notification_id=keys[0])
            case "BUS2128":
                return self.get_maintenance_order_confirmation(confirmation_id=keys[0], counter=keys[1])
            case "BUS1020":
                return self.get_maintenance_plan(plan_id=keys[0])
            case "BUS1019":
                return self.get_task_list(
                    task_list_type=keys[0], task_list_group=keys[1], task_list_group_counter=keys[2]
                )
            case "BUS2012":
                return self.get_purchase_order(order_id=keys[0])
            case "BUS2105":
                return self.get_purchase_requisition(requisition_id=keys[0])
            case "BUS2014":
                return self.get_purchase_contract(contract_id=keys[0])
            case "BUS2081":
                return self.get_supplier_invoice(invoice_id=keys[0], fiscal_year=keys[1])
            case "BUS2032":
                return self.get_sales_order(order_id=keys[0])
            case "BUS2034":
                return self.get_sales_contract(contract_id=keys[0])
            case "BUS2094":
                return self.get_credit_memo_request(credit_memo_request_id=keys[0])
            case "BUS2096":
                return self.get_debit_memo_request(debit_memo_request_id=keys[0])
            case "VBRK" | "BUS2037":
                return self.get_billing_document(billing_document_id=keys[0])
            case "LIKP":
                return self.get_outbound_delivery(delivery_id=keys[0])
            case "BUS2015":
                return self.get_inbound_delivery(delivery_id=keys[0])
            case "BUS2017":
                return self.get_goods_movement(document=keys[0], document_year=keys[1])
            case "BUS2004":
                return self.get_planned_order(planned_order_id=keys[0])
            case "BUS2005":
                return self.get_production_order(order_id=keys[0])
            case "EQUI":
                return self.get_equipment(equipment_id=keys[0])
            case "BUS0010":
                return self.get_functional_location(functional_location_id=keys[0])
            case "BUS1001006" | "BUS1001":
                return self.get_product(product_id=keys[0])
            case "BUS1006":
                return self.get_business_partner(business_partner_id=keys[0])
            case "KNA1":
                return self.get_customer(customer_id=keys[0])
            case "LFA1":
                return self.get_supplier(supplier_id=keys[0])
            case "BUS0002":
                return self.get_company_code(company_code=keys[0])
            case "BUS0012":
                return self.get_cost_center(controlling_area=keys[0], cost_center=keys[1])
            case "BUS0015":
                return self.get_profit_center(controlling_area=keys[0], profit_center=keys[1])
            case _:
                self.log_error("Unsupported SAP business object type -> '%s' with ID -> '%s'.", bo_type, bo_id)
                return None

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
        params = (
            {"$expand": "to_MaintenanceOrderOperation,to_MaintenanceOrderOperation/to_MaintOrderOpComponent_2"}
            if expand_operations
            else None
        )

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

    def get_maintenance_order_deletion_steps(self, order_id: str) -> list[SAPMaintenanceOrderAction] | None:
        """Return the status actions needed to delete an SAP maintenance order (see delete_maintenance_order()).

        SAP only accepts the deletion flag for closed orders - the order is closed first, depending on its status:
        * Created (CRTD, not released): DO_NOT_EXECUTE - closes the order as not performed (CLSD NCMP).
        * Released (REL): TECHNICALLY_COMPLETE (TECO) and CLOSE (CLSD).
        * Technically completed (TECO): CLOSE.
        * Closed (CLSD): nothing.
        The last step is always MARK_FOR_DELETION.

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".

        Returns:
            list[SAPMaintenanceOrderAction] | None:
                The status actions in their order - empty if the order already has the
                deletion flag - or None if the order does not exist or in case of an error.

        """

        order = self.get_maintenance_order(order_id=order_id, expand_operations=False)
        if order is None:
            return None

        statuses = set((order.system_status or "").split())
        if "DLFL" in statuses:
            return []

        steps = []
        if "CLSD" not in statuses:
            if "REL" not in statuses and "TECO" not in statuses:
                steps.append(SAPMaintenanceOrderAction.DO_NOT_EXECUTE)
            else:
                if "TECO" not in statuses:
                    steps.append(SAPMaintenanceOrderAction.TECHNICALLY_COMPLETE)
                steps.append(SAPMaintenanceOrderAction.CLOSE)
        steps.append(SAPMaintenanceOrderAction.MARK_FOR_DELETION)

        return steps

    # end method definition

    def delete_maintenance_order(
        self,
        order_id: str,
        include_notification: bool = True,
        steps: list[SAPMaintenanceOrderAction] | None = None,
    ) -> bool:
        """Delete an SAP maintenance order by setting its deletion flag (status DLFL).

        API_MAINTENANCEORDER has no OData DELETE and SAP only accepts the deletion flag
        for closed orders (otherwise: IW/875 "You cannot change the status of order").
        This method closes the order first, depending on its status (see
        get_maintenance_order_deletion_steps()):
        * Created (CRTD, not released): "do not execute" - closes the order as not
          performed (CLSD NCMP).
        * Released (REL): technically complete (TECO) and close (CLSD). This needs a
          settlement rule of the order - SAP rejects it otherwise with
          "account assignment not maintained".
        The deletion flag can be removed again with SAPMaintenanceOrderAction.RESET_MARKED_FOR_DELETION.

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            include_notification (bool, optional):
                Whether the assigned maintenance notification is completed and gets the
                deletion flag as well. Defaults to True.
            steps (list[SAPMaintenanceOrderAction] | None, optional):
                The status actions to do - e.g. the result of get_maintenance_order_deletion_steps()
                the user has confirmed. Defaults to None = determine them from the current status.

        Returns:
            bool:
                True if the order has the deletion flag, False in case of an error.

        """

        if steps is None:
            steps = self.get_maintenance_order_deletion_steps(order_id=order_id)
            if steps is None:
                return False
        if not steps:
            self.logger.info("SAP maintenance order -> '%s' already has the deletion flag.", order_id)
            return True

        for action in steps:
            if action == SAPMaintenanceOrderAction.MARK_FOR_DELETION:
                parameters = {"AssgdMaintNotifIsToBeSetDel": include_notification}
            else:
                parameters = {"AssignedMaintNotifIsToBeClosed": include_notification}
            # Stop at the first error - the next steps need the status of this one:
            if not self.change_maintenance_order_status(order_id=order_id, action=action, parameters=parameters):
                return False

        return True

    # end method definition

    def _maintenance_order_operation_path(self, order_id: str, operation: str, sub_operation: str = "") -> str:
        """Return the OData path of a maintenance order operation (its key has three parts).

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            operation (str):
                The operation number, e.g. "10" or "0010" (padded to 4 digits).
            sub_operation (str, optional):
                The sub-operation number. Empty (default) for operations.

        Returns:
            str:
                The path relative to the service root, e.g.
                "MaintenanceOrderOperation(MaintenanceOrder='4000340',MaintenanceOrderOperation='0010',
                MaintenanceOrderSubOperation='')".

        Raises:
            ValueError:
                If the operation or sub-operation number is not numeric or too long.

        """

        return (
            "MaintenanceOrderOperation(MaintenanceOrder='{}',MaintenanceOrderOperation='{}',"
            "MaintenanceOrderSubOperation='{}')".format(
                self._quote_key(order_id),
                pad_number(operation, length=4),
                pad_number(sub_operation, length=4) if sub_operation else "",
            )
        )

    # end method definition

    def create_maintenance_order_operation(
        self,
        order_id: str,
        operation: SAPMaintenanceOrderOperationModel | dict,
    ) -> dict | None:
        """Add an operation (work step) to an existing SAP maintenance order.

        The operation is created via the navigation property of the order (the entity set
        MaintenanceOrderOperation itself does not allow creates).

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            operation (SAPMaintenanceOrderOperationModel | dict):
                The new operation. The operation number must not exist in the order yet.

        Returns:
            dict | None:
                The created operation as returned by SAP or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_MAINTENANCEORDER",
            entity_set="MaintenanceOrder('{}')/to_MaintenanceOrderOperation".format(self._quote_key(order_id)),
            model=SAPMaintenanceOrderOperationModel,
            data=operation,
            key_fields=["MaintenanceOrder", "MaintenanceOrderOperation"],
            label="operation of maintenance order -> '{}'".format(order_id),
        )

    # end method definition

    def update_maintenance_order_operation(
        self,
        order_id: str,
        operation: str,
        changes: dict,
        sub_operation: str = "",
    ) -> bool:
        """Update individual fields of an operation of an SAP maintenance order.

        The changes are validated with the field definitions of SAPMaintenanceOrderOperationModel.

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            operation (str):
                The operation number, e.g. "10" or "0010".
            changes (dict):
                The fields to change - snake case attribute names of SAPMaintenanceOrderOperationModel
                or OData property names, e.g. {"planned_work": 6, "planned_work_unit": "H"}.
            sub_operation (str, optional):
                The sub-operation number. Empty (default) for operations.

        Returns:
            bool:
                True if the operation has been updated, False in case of an error.

        """

        label = "operation -> '{}' of maintenance order -> '{}'".format(operation, order_id)
        try:
            entity_path = self._maintenance_order_operation_path(order_id, operation, sub_operation)
        except ValueError as value_error:
            self.log_error("Invalid key of SAP %s; error -> %s", label, str(value_error))
            return False

        return self._update_odata_entity(
            service="API_MAINTENANCEORDER",
            entity_path=entity_path,
            model=SAPMaintenanceOrderOperationModel,
            changes=changes,
            label=label,
        )

    # end method definition

    def delete_maintenance_order_operation(self, order_id: str, operation: str, sub_operation: str = "") -> bool:
        """Delete an operation of an SAP maintenance order.

        Operations of orders that are not released yet (status CRTD) are removed. For
        released orders SAP typically keeps the operation with its deletion flag
        (IsMarkedForDeletion) - it is no longer planned or executed. Operations with
        confirmations or follow-on documents (e.g. purchase requisitions) cannot be deleted.

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            operation (str):
                The operation number, e.g. "10" or "0010".
            sub_operation (str, optional):
                The sub-operation number. Empty (default) for operations.

        Returns:
            bool:
                True if the operation has been deleted, False in case of an error.

        """

        label = "operation -> '{}' of maintenance order -> '{}'".format(operation, order_id)
        try:
            entity_path = self._maintenance_order_operation_path(order_id, operation, sub_operation)
        except ValueError as value_error:
            self.log_error("Invalid key of SAP %s; error -> %s", label, str(value_error))
            return False

        return self._delete_odata_entity(service="API_MAINTENANCEORDER", entity_path=entity_path, label=label)

    # end method definition

    def change_maintenance_order_operation_status(
        self,
        order_id: str,
        operation: str,
        action: SAPMaintenanceOrderOperationAction,
        sub_operation: str = "",
    ) -> bool:
        """Change the status of an operation of an SAP maintenance order (e.g. dispatch it).

        Args:
            order_id (str):
                The maintenance order number, e.g. "4000340".
            operation (str):
                The operation number, e.g. "10" or "0010".
            action (SAPMaintenanceOrderOperationAction):
                The status action, e.g. SAPMaintenanceOrderOperationAction.DISPATCH.
            sub_operation (str, optional):
                The sub-operation number. Empty (default) for operations.

        Returns:
            bool:
                True if the status has been changed, False in case of an error.

        """

        label = "{} operation -> '{}' of maintenance order -> '{}'".format(
            action.name.lower().replace("_", " "), operation, order_id
        )
        try:
            operation = pad_number(operation, length=4)
            sub_operation = pad_number(sub_operation, length=4) if sub_operation else ""
        except ValueError as value_error:
            self.log_error("Cannot %s; error -> %s", label, str(value_error))
            return False

        result = self._call_odata_function(
            service="API_MAINTENANCEORDER",
            function=str(action),
            parameters={
                "MaintenanceOrder": order_id,
                "MaintenanceOrderOperation": operation,
                "MaintenanceOrderSubOperation": sub_operation,
            },
            label=label,
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

    def update_purchase_order(
        self, order_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP purchase order and of its items.

        All changes are validated first and the items must belong to the purchase order - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        Args:
            order_id (str):
                The purchase order number, e.g. "4500001586".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPPurchaseOrderModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"10": {"OrderQuantity": 20}} (snake case attribute names of SAPPurchaseOrderItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the purchase order (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(order_id)

        return self._update_odata_document(
            service="API_PURCHASEORDER_2",
            label="purchase order -> '{}'".format(order_id),
            header_path="PurchaseOrder('{}')".format(key),
            header_model=SAPPurchaseOrderModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="PurchaseOrder('{}')/_PurchaseOrderItem".format(key),
                entity_set="PurchaseOrderItem",
                key_properties=("PurchaseOrder", "PurchaseOrderItem"),
                number_property="PurchaseOrderItem",
                text_property="PurchaseOrderItemText",
                label="item",
            ),
            item_model=SAPPurchaseOrderItemModel,
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

    def update_maintenance_notification(
        self, notification_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP maintenance notification and of its items.

        All changes are validated first and the items must belong to the maintenance notification - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).
        The codes of an item (damage, object part) can be set or replaced, but not removed (SAP only
        allows this in its UI).

        Args:
            notification_id (str):
                The maintenance notification number, e.g. "10000239".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPMaintenanceNotificationModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"1": {"MaintNotifItemText": "Seal leak"}} (snake case attribute names of SAPMaintenanceNotificationItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the maintenance notification (and its items) have been updated, False in case of an error.

        """

        # SAP cannot remove the codes of an item with the API - only replace them ("IM/150 Please enter
        # code for code group" / "EAMS_BO/124 To delete codes and code groups, use the 'Remove' pushbutton"):
        codes = (
            "MaintNotifDamageCodeGroup",
            "MaintNotificationDamageCode",
            "MaintNotifObjPrtCodeGroup",
            "MaintNotifObjPrtCode",
        )
        for item, item_change in (item_changes or {}).items():
            try:
                payload = SAPMaintenanceNotificationItemModel.to_odata_update(item_change)
            except ValueError:
                continue  # reported by _update_odata_document()
            if removed := [code for code in codes if code in payload and not payload[code]]:
                self.log_error(
                    "SAP cannot remove the codes -> %s of item -> '%s' of maintenance notification -> '%s' with the "
                    "API - codes can only be replaced by other codes. Remove them in SAP (e.g. in the app 'Change "
                    "Maintenance Notification').",
                    ", ".join(removed),
                    item,
                    notification_id,
                )
                return False

        key = self._quote_key(notification_id)

        return self._update_odata_document(
            service="API_MAINTNOTIFICATION",
            label="maintenance notification -> '{}'".format(notification_id),
            header_path="MaintenanceNotification('{}')".format(key),
            header_model=SAPMaintenanceNotificationModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="MaintenanceNotification('{}')/to_Item".format(key),
                entity_set="MaintenanceNotificationItem",
                key_properties=("MaintenanceNotification", "MaintenanceNotificationItem"),
                number_property="MaintenanceNotificationItem",
                text_property="MaintNotifItemText",
                label="item",
            ),
            item_model=SAPMaintenanceNotificationItemModel,
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
            # RAP based service - its functions need the ETag of the notification (428 Precondition required otherwise):
            etag_entity_path="MaintenanceNotification('{}')".format(self._quote_key(notification_id)),
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

    def update_sales_order(
        self, order_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP sales order and of its items.

        All changes are validated first and the items must belong to the sales order - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        Args:
            order_id (str):
                The sales order number, e.g. "413".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPSalesOrderModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"10": {"RequestedQuantity": 5}} (snake case attribute names of SAPSalesOrderItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the sales order (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(order_id)

        return self._update_odata_document(
            service="API_SALES_ORDER_SRV",
            label="sales order -> '{}'".format(order_id),
            header_path="A_SalesOrder('{}')".format(key),
            header_model=SAPSalesOrderModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="A_SalesOrder('{}')/to_Item".format(key),
                entity_set="A_SalesOrderItem",
                key_properties=("SalesOrder", "SalesOrderItem"),
                number_property="SalesOrderItem",
                text_property="SalesOrderItemText",
                label="item",
            ),
            item_model=SAPSalesOrderItemModel,
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

    def update_sales_contract(
        self, contract_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP sales contract and of its items.

        All changes are validated first and the items must belong to the sales contract - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        Args:
            contract_id (str):
                The sales contract number, e.g. "40000039".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPSalesContractModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"10": {"RequestedQuantity": 100}} (snake case attribute names of SAPSalesContractItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the sales contract (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(contract_id)

        return self._update_odata_document(
            service="API_SALES_CONTRACT_SRV",
            label="sales contract -> '{}'".format(contract_id),
            header_path="A_SalesContract('{}')".format(key),
            header_model=SAPSalesContractModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="A_SalesContract('{}')/to_Item".format(key),
                entity_set="A_SalesContractItem",
                key_properties=("SalesContract", "SalesContractItem"),
                number_property="SalesContractItem",
                text_property="SalesContractItemText",
                label="item",
            ),
            item_model=SAPSalesContractItemModel,
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

    def update_purchase_contract(
        self, contract_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP purchase contract and of its items.

        All changes are validated first and the items must belong to the purchase contract - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        A deleted item is restored with the item change {"PurchasingContractDeletionCode": ""}.
        Some S/4HANA releases reject all header changes with "Purchase contract cannot be saved in
        preparation" (versions 0001 and 0002 of the API) while item changes work.

        Args:
            contract_id (str):
                The purchase contract number, e.g. "4600000070".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPPurchaseContractModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"10": {"net_price": 925.00}} (snake case attribute names of SAPPurchaseContractItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the purchase contract (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(contract_id)

        return self._update_odata_document(
            service="API_PURCHASECONTRACT_PROCESS_SRV",
            label="purchase contract -> '{}'".format(contract_id),
            header_path="A_PurchaseContract('{}')".format(key),
            header_model=SAPPurchaseContractModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="A_PurchaseContract('{}')/to_PurchaseContractItem".format(key),
                entity_set="A_PurchaseContractItem",
                key_properties=("PurchaseContract", "PurchaseContractItem"),
                number_property="PurchaseContractItem",
                text_property="PurchaseContractItemText",
                label="item",
            ),
            item_model=SAPPurchaseContractItemModel,
        )

    # end method definition

    def update_purchase_contract_item(self, contract_id: str, item: str, changes: dict) -> bool:
        """Update individual fields of an item of an SAP purchase contract.

        The changes are validated with the field definitions of SAPPurchaseContractItemModel.
        To change the header and several items at once, use update_purchase_contract().
        The deletion indicator of the item can be changed with the OData property
        "PurchasingContractDeletionCode" ("L" = deleted, "S" = blocked, "" = active).

        Args:
            contract_id (str):
                The purchase contract number, e.g. "4600000070".
            item (str):
                The item number, e.g. "10" or "00010".
            changes (dict):
                The fields to change - snake case attribute names of SAPPurchaseContractItemModel or
                OData property names, e.g. {"net_price": 925.00}.

        Returns:
            bool:
                True if the item has been updated, False in case of an error.

        """

        label = "item -> '{}' of purchase contract -> '{}'".format(item, contract_id)
        try:
            item = pad_number(item, length=5)
        except ValueError as value_error:
            self.log_error("Invalid key of SAP %s; error -> %s", label, str(value_error))
            return False

        return self._update_odata_entity(
            service="API_PURCHASECONTRACT_PROCESS_SRV",
            entity_path="A_PurchaseContractItem(PurchaseContract='{}',PurchaseContractItem='{}')".format(
                self._quote_key(contract_id), item
            ),
            model=SAPPurchaseContractItemModel,
            changes=changes,
            label=label,
        )

    # end method definition

    def delete_purchase_contract(self, contract_id: str, items: list[str] | None = None) -> bool:
        """Delete an SAP purchase contract or some of its items (set their deletion indicator).

        API_PURCHASECONTRACT_PROCESS_SRV does not allow DELETE - like in SAP GUI
        (ME32K), contracts are deleted by setting the deletion indicator "L" of their
        items. Deleted items can no longer be referenced by purchase orders. The
        deletion can be undone per item with update_purchase_contract() and the item change
        {"PurchasingContractDeletionCode": ""}.

        Args:
            contract_id (str):
                The purchase contract number, e.g. "4600000070".
            items (list[str] | None, optional):
                The item numbers to delete, e.g. ["10"]. Defaults to None = all items.

        Returns:
            bool:
                True if all (given) items are deleted, False in case of an error.

        """

        contract = self.get_purchase_contract(contract_id=contract_id, expand_items=True)
        if contract is None:
            return False

        try:
            wanted = {pad_number(item, length=5) for item in items} if items is not None else None
        except ValueError as value_error:
            self.log_error("Invalid item of SAP purchase contract -> '%s'; error -> %s", contract_id, str(value_error))
            return False

        existing = {item.item: item for item in contract.items or []}
        if wanted is not None and (unknown := wanted - existing.keys()):
            self.log_error(
                "SAP purchase contract -> '%s' has no item(s) -> %s!", contract_id, ", ".join(sorted(unknown))
            )
            return False
        if not existing:
            self.log_error("SAP purchase contract -> '%s' has no items to delete!", contract_id)
            return False

        for number, item in existing.items():
            if (wanted is not None and number not in wanted) or item.deletion_code == "L":
                continue
            # Stop at the first error - a later successful request would reset last_error:
            if not self.update_purchase_contract_item(
                contract_id=contract_id,
                item=number,
                changes={"PurchasingContractDeletionCode": "L"},
            ):
                return False

        return True

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

    def update_purchase_requisition(
        self, requisition_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP purchase requisition and of its items.

        All changes are validated first and the items must belong to the purchase requisition - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        Args:
            requisition_id (str):
                The purchase requisition number, e.g. "10000175".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPPurchaseRequisitionModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"10": {"RequestedQuantity": 5}} (snake case attribute names of SAPPurchaseRequisitionItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the purchase requisition (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(requisition_id)

        return self._update_odata_document(
            service="API_PURCHASEREQUISITION_2",
            label="purchase requisition -> '{}'".format(requisition_id),
            header_path="PurchaseReqn('{}')".format(key),
            header_model=SAPPurchaseRequisitionModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="PurchaseReqn('{}')/_PurchaseRequisitionItem".format(key),
                entity_set="PurchaseReqnItem",
                key_properties=("PurchaseRequisition", "PurchaseRequisitionItem"),
                number_property="PurchaseRequisitionItem",
                text_property="PurchaseRequisitionItemText",
                label="item",
            ),
            item_model=SAPPurchaseRequisitionItemModel,
        )

    # end method definition

    def create_credit_memo_request(self, request: SAPCreditMemoRequestModel | dict) -> dict | None:
        """Create an SAP credit memo request (including its items).

        Uses the OData V2 API API_CREDIT_MEMO_REQUEST_SRV with a deep insert. SAP creates the
        credit memo (a billing document) from the request - usually after an approval.

        Args:
            request (SAPCreditMemoRequestModel | dict):
                The data. A dictionary is validated against the SAPCreditMemoRequestModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created credit memo request as returned by SAP (including the number in
                "CreditMemoRequest") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_CREDIT_MEMO_REQUEST_SRV",
            entity_set="A_CreditMemoRequest",
            model=SAPCreditMemoRequestModel,
            data=request,
            key_fields=["CreditMemoRequest"],
            label="credit memo request",
        )

    # end method definition

    def iter_credit_memo_requests(
        self, query: SAPCreditMemoRequestQueryModel | None = None
    ) -> SAPODataIterator[SAPCreditMemoRequestResponseModel]:
        """Iterate over SAP credit memo requests - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPCreditMemoRequestQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all credit memo requests).

        Returns:
            SAPODataIterator[SAPCreditMemoRequestResponseModel]:
                The iterator over the credit memo requests.

        """

        return self._iter_odata_collection(
            service="API_CREDIT_MEMO_REQUEST_SRV",
            entity_set="A_CreditMemoRequest",
            model=SAPCreditMemoRequestResponseModel,
            query=query or SAPCreditMemoRequestQueryModel(),
            label="credit memo requests",
        )

    # end method definition

    def get_credit_memo_requests(
        self, query: SAPCreditMemoRequestQueryModel | None = None
    ) -> list[SAPCreditMemoRequestResponseModel] | None:
        """Get SAP credit memo requests as a list.

        All matching credit memo requests are read (page by page, see iter_credit_memo_requests()) and returned at once.
        For very large result sets prefer iter_credit_memo_requests().

        Args:
            query (SAPCreditMemoRequestQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all credit memo requests).

        Returns:
            list[SAPCreditMemoRequestResponseModel] | None:
                The credit memo requests (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_credit_memo_requests(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP credit memo requests.", len(results))

        return results

    # end method definition

    def get_credit_memo_request(
        self, request_id: str, expand_items: bool = True
    ) -> SAPCreditMemoRequestResponseModel | None:
        """Get a single SAP credit memo request.

        Args:
            request_id (str):
                The credit memo request number, e.g. "60000012".
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPCreditMemoRequestResponseModel | None:
                The credit memo request or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_CREDIT_MEMO_REQUEST_SRV",
            entity_path="A_CreditMemoRequest('{}')".format(self._quote_key(request_id)),
            model=SAPCreditMemoRequestResponseModel,
            params={"$expand": "to_Item"} if expand_items else None,
            label="credit memo request -> '{}'".format(request_id),
        )

    # end method definition

    def update_credit_memo_request(
        self, request_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP credit memo request and of its items.

        All changes are validated first and the items must belong to the credit memo request - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        Args:
            request_id (str):
                The credit memo request number, e.g. "60000012".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPCreditMemoRequestModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"10": {"RequestedQuantity": 1}} (snake case attribute names of SAPCreditMemoRequestItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the credit memo request (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(request_id)

        return self._update_odata_document(
            service="API_CREDIT_MEMO_REQUEST_SRV",
            label="credit memo request -> '{}'".format(request_id),
            header_path="A_CreditMemoRequest('{}')".format(key),
            header_model=SAPCreditMemoRequestModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="A_CreditMemoRequest('{}')/to_Item".format(key),
                entity_set="A_CreditMemoRequestItem",
                key_properties=("CreditMemoRequest", "CreditMemoRequestItem"),
                number_property="CreditMemoRequestItem",
                text_property="CreditMemoRequestItemText",
                label="item",
            ),
            item_model=SAPCreditMemoRequestItemModel,
        )

    # end method definition

    def delete_credit_memo_request(self, request_id: str) -> bool:
        """Delete an SAP credit memo request.

        Args:
            request_id (str):
                The credit memo request number, e.g. "60000012".

        Returns:
            bool:
                True if the credit memo request has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_CREDIT_MEMO_REQUEST_SRV",
            entity_path="A_CreditMemoRequest('{}')".format(self._quote_key(request_id)),
            label="credit memo request -> '{}'".format(request_id),
        )

    # end method definition

    def change_credit_memo_request_status(self, request_id: str, action: SAPCreditMemoRequestAction) -> bool:
        """Approve (release) or reject an SAP credit memo request that is in approval.

        Args:
            request_id (str):
                The credit memo request number, e.g. "60000012".
            action (SAPCreditMemoRequestAction):
                The approval action, e.g. SAPCreditMemoRequestAction.RELEASE_APPROVAL_REQUEST.

        Returns:
            bool:
                True if the status has been changed, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_CREDIT_MEMO_REQUEST_SRV",
            function=str(action),
            parameters={"CreditMemoRequest": request_id},
            label="{} credit memo request -> '{}'".format(action.name.lower().replace("_", " "), request_id),
        )

        return result is not None

    # end method definition

    def create_debit_memo_request(self, request: SAPDebitMemoRequestModel | dict) -> dict | None:
        """Create an SAP debit memo request (including its items).

        Uses the OData V2 API API_DEBIT_MEMO_REQUEST_SRV with a deep insert. SAP creates the
        debit memo (a billing document) from the request.

        Args:
            request (SAPDebitMemoRequestModel | dict):
                The data. A dictionary is validated against the SAPDebitMemoRequestModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created debit memo request as returned by SAP (including the number in
                "DebitMemoRequest") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_DEBIT_MEMO_REQUEST_SRV",
            entity_set="A_DebitMemoRequest",
            model=SAPDebitMemoRequestModel,
            data=request,
            key_fields=["DebitMemoRequest"],
            label="debit memo request",
        )

    # end method definition

    def iter_debit_memo_requests(
        self, query: SAPDebitMemoRequestQueryModel | None = None
    ) -> SAPODataIterator[SAPDebitMemoRequestResponseModel]:
        """Iterate over SAP debit memo requests - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPDebitMemoRequestQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all debit memo requests).

        Returns:
            SAPODataIterator[SAPDebitMemoRequestResponseModel]:
                The iterator over the debit memo requests.

        """

        return self._iter_odata_collection(
            service="API_DEBIT_MEMO_REQUEST_SRV",
            entity_set="A_DebitMemoRequest",
            model=SAPDebitMemoRequestResponseModel,
            query=query or SAPDebitMemoRequestQueryModel(),
            label="debit memo requests",
        )

    # end method definition

    def get_debit_memo_requests(
        self, query: SAPDebitMemoRequestQueryModel | None = None
    ) -> list[SAPDebitMemoRequestResponseModel] | None:
        """Get SAP debit memo requests as a list.

        All matching debit memo requests are read (page by page, see iter_debit_memo_requests()) and returned at once.
        For very large result sets prefer iter_debit_memo_requests().

        Args:
            query (SAPDebitMemoRequestQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all debit memo requests).

        Returns:
            list[SAPDebitMemoRequestResponseModel] | None:
                The debit memo requests (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_debit_memo_requests(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP debit memo requests.", len(results))

        return results

    # end method definition

    def get_debit_memo_request(
        self, request_id: str, expand_items: bool = True
    ) -> SAPDebitMemoRequestResponseModel | None:
        """Get a single SAP debit memo request.

        Args:
            request_id (str):
                The debit memo request number, e.g. "70000012".
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPDebitMemoRequestResponseModel | None:
                The debit memo request or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_DEBIT_MEMO_REQUEST_SRV",
            entity_path="A_DebitMemoRequest('{}')".format(self._quote_key(request_id)),
            model=SAPDebitMemoRequestResponseModel,
            params={"$expand": "to_Item"} if expand_items else None,
            label="debit memo request -> '{}'".format(request_id),
        )

    # end method definition

    def update_debit_memo_request(
        self, request_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP debit memo request and of its items.

        All changes are validated first and the items must belong to the debit memo request - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        Args:
            request_id (str):
                The debit memo request number, e.g. "70000012".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPDebitMemoRequestModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"10": {"RequestedQuantity": 1}} (snake case attribute names of SAPDebitMemoRequestItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the debit memo request (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(request_id)

        return self._update_odata_document(
            service="API_DEBIT_MEMO_REQUEST_SRV",
            label="debit memo request -> '{}'".format(request_id),
            header_path="A_DebitMemoRequest('{}')".format(key),
            header_model=SAPDebitMemoRequestModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="A_DebitMemoRequest('{}')/to_Item".format(key),
                entity_set="A_DebitMemoRequestItem",
                key_properties=("DebitMemoRequest", "DebitMemoRequestItem"),
                number_property="DebitMemoRequestItem",
                text_property="DebitMemoRequestItemText",
                label="item",
            ),
            item_model=SAPDebitMemoRequestItemModel,
        )

    # end method definition

    def delete_debit_memo_request(self, request_id: str) -> bool:
        """Delete an SAP debit memo request.

        Args:
            request_id (str):
                The debit memo request number, e.g. "70000012".

        Returns:
            bool:
                True if the debit memo request has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_DEBIT_MEMO_REQUEST_SRV",
            entity_path="A_DebitMemoRequest('{}')".format(self._quote_key(request_id)),
            label="debit memo request -> '{}'".format(request_id),
        )

    # end method definition

    def iter_billing_document_requests(
        self, query: SAPBillingDocumentRequestQueryModel | None = None
    ) -> SAPODataIterator[SAPBillingDocumentRequestResponseModel]:
        """Iterate over SAP billing document requests - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPBillingDocumentRequestQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all requests).

        Returns:
            SAPODataIterator[SAPBillingDocumentRequestResponseModel]:
                The iterator over the billing document requests.

        """

        return self._iter_odata_collection(
            service="API_BILLING_DOCUMENT_REQUEST_SRV",
            entity_set="A_BillingDocumentRequest",
            model=SAPBillingDocumentRequestResponseModel,
            query=query or SAPBillingDocumentRequestQueryModel(),
            label="billing document requests",
        )

    # end method definition

    def get_billing_document_requests(
        self, query: SAPBillingDocumentRequestQueryModel | None = None
    ) -> list[SAPBillingDocumentRequestResponseModel] | None:
        """Get SAP billing document requests as a list.

        All matching requests are read (page by page, see iter_billing_document_requests()) and returned at once.
        For very large result sets prefer iter_billing_document_requests().

        Args:
            query (SAPBillingDocumentRequestQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all requests).

        Returns:
            list[SAPBillingDocumentRequestResponseModel] | None:
                The billing document requests (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_billing_document_requests(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP billing document requests.", len(results))

        return results

    # end method definition

    def get_billing_document_request(
        self, request_id: str, expand_items: bool = True
    ) -> SAPBillingDocumentRequestResponseModel | None:
        """Get a single SAP billing document request.

        Args:
            request_id (str):
                The billing document request number.
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPBillingDocumentRequestResponseModel | None:
                The billing document request or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_BILLING_DOCUMENT_REQUEST_SRV",
            entity_path="A_BillingDocumentRequest('{}')".format(self._quote_key(request_id)),
            model=SAPBillingDocumentRequestResponseModel,
            params={"$expand": "to_Item"} if expand_items else None,
            label="billing document request -> '{}'".format(request_id),
        )

    # end method definition

    def delete_billing_document_request(self, request_id: str) -> bool:
        """Delete an SAP billing document request (that has not been billed yet).

        Args:
            request_id (str):
                The billing document request number.

        Returns:
            bool:
                True if the billing document request has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_BILLING_DOCUMENT_REQUEST_SRV",
            entity_path="A_BillingDocumentRequest('{}')".format(self._quote_key(request_id)),
            label="billing document request -> '{}'".format(request_id),
        )

    # end method definition

    def reject_billing_document_request(self, request_id: str) -> bool:
        """Reject an SAP billing document request - it will not be billed.

        Args:
            request_id (str):
                The billing document request number.

        Returns:
            bool:
                True if the billing document request has been rejected, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_BILLING_DOCUMENT_REQUEST_SRV",
            function="Reject",
            parameters={"BillingDocumentRequest": request_id},
            label="reject billing document request -> '{}'".format(request_id),
        )
        if result is None:
            return False

        # SAP reports business errors in the result (HTTP 200) - e.g. if the request is already billed:
        result = result.get("Reject", result)
        if result.get("MessageType") in ("E", "A"):
            self.log_error(
                "Cannot reject SAP billing document request -> '%s'; message -> %s", request_id, result.get("Message")
            )
            return False

        return True

    # end method definition

    def iter_billing_documents(
        self, query: SAPBillingDocumentQueryModel | None = None
    ) -> SAPODataIterator[SAPBillingDocumentResponseModel]:
        """Iterate over SAP billing documents (customer invoices, credit / debit memos) - reading them page by page.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPBillingDocumentQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all billing documents).
                The sales orders (an item property) are resolved via the billing document items first.

        Returns:
            SAPODataIterator[SAPBillingDocumentResponseModel]:
                The iterator over the billing documents.

        """

        query = query or SAPBillingDocumentQueryModel()

        if query.sales_orders:
            # A_BillingDocument cannot be filtered by its items (OData V2 has no any()) - find the
            # billing documents of the sales orders via their items, then read them by their IDs:
            items = self.iter_billing_document_items(
                query=SAPBillingDocumentItemQueryModel(
                    sales_orders=query.sales_orders, billing_document_ids=query.billing_document_ids
                )
            )
            billing_document_ids = list(dict.fromkeys(item.billing_document_id for item in items))
            if items.failed:
                return SAPODataIterator(_failed_odata_read())
            if not billing_document_ids:
                self.logger.info("No SAP billing documents for sales orders -> %s.", str(query.sales_orders))
                return SAPODataIterator(iter([]))
            query = query.model_copy(update={"billing_document_ids": billing_document_ids, "sales_orders": None})

        return self._iter_odata_collection(
            service="API_BILLING_DOCUMENT_SRV",
            entity_set="A_BillingDocument",
            model=SAPBillingDocumentResponseModel,
            query=query,
            label="billing documents",
        )

    # end method definition

    def iter_billing_document_items(
        self, query: SAPBillingDocumentItemQueryModel | None = None
    ) -> SAPODataIterator[SAPBillingDocumentItemResponseModel]:
        """Iterate over SAP billing document items - reading them page by page.

        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPBillingDocumentItemQueryModel | None, optional):
                The search criteria, e.g. the sales orders the items were billed for.
                Defaults to None (all billing document items).

        Returns:
            SAPODataIterator[SAPBillingDocumentItemResponseModel]:
                The iterator over the billing document items.

        """

        return self._iter_odata_collection(
            service="API_BILLING_DOCUMENT_SRV",
            entity_set="A_BillingDocumentItem",
            model=SAPBillingDocumentItemResponseModel,
            query=query or SAPBillingDocumentItemQueryModel(),
            label="billing document items",
        )

    # end method definition

    def get_billing_documents(
        self, query: SAPBillingDocumentQueryModel | None = None
    ) -> list[SAPBillingDocumentResponseModel] | None:
        """Get SAP billing documents (customer invoices, credit / debit memos) as a list.

        All matching billing documents are read (page by page, see iter_billing_documents()) and returned at once.
        For very large result sets prefer iter_billing_documents().

        Args:
            query (SAPBillingDocumentQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all billing documents).

        Returns:
            list[SAPBillingDocumentResponseModel] | None:
                The billing documents (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_billing_documents(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP billing documents.", len(results))

        return results

    # end method definition

    def get_billing_document(
        self, billing_document_id: str, expand_items: bool = True
    ) -> SAPBillingDocumentResponseModel | None:
        """Get a single SAP billing document (customer invoice, credit / debit memo).

        Args:
            billing_document_id (str):
                The billing document number, e.g. "90000123".
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPBillingDocumentResponseModel | None:
                The billing document or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_BILLING_DOCUMENT_SRV",
            entity_path="A_BillingDocument('{}')".format(self._quote_key(billing_document_id)),
            model=SAPBillingDocumentResponseModel,
            params={"$expand": "to_Item"} if expand_items else None,
            label="billing document -> '{}'".format(billing_document_id),
        )

    # end method definition

    def cancel_billing_document(self, billing_document_id: str) -> dict | None:
        """Cancel an SAP billing document - SAP creates a cancellation billing document.

        Args:
            billing_document_id (str):
                The billing document number, e.g. "90000123".

        Returns:
            dict | None:
                The result (including the cancellation document in "CancellationBillingDocument")
                or None in case of an error.

        """

        result = self._call_odata_function(
            service="API_BILLING_DOCUMENT_SRV",
            function="Cancel",
            parameters={"BillingDocument": billing_document_id},
            label="cancel billing document -> '{}'".format(billing_document_id),
            # Cancel needs the ETag of the billing document (428 Precondition required otherwise, SAP note 3101527):
            etag_entity_path="A_BillingDocument('{}')".format(self._quote_key(billing_document_id)),
        )
        if result is None:
            return None

        # SAP returns a list of results and reports business errors in them (HTTP 200):
        results = result.get("results", [result])
        errors = [entry.get("SystemMessageText") for entry in results if entry.get("SystemMessageType") in ("E", "A")]
        if errors or not results or not results[0].get("CancellationBillingDocument"):
            self.log_error(
                "Cannot cancel SAP billing document -> '%s'; messages -> %s",
                billing_document_id,
                str(errors or results),
            )
            return None

        return results[0]

    # end method definition

    def get_billing_document_pdf(self, billing_document_id: str) -> bytes | None:
        """Get the PDF (print form) of an SAP billing document - e.g. the invoice as sent to the customer.

        Args:
            billing_document_id (str):
                The billing document number, e.g. "90000123".

        Returns:
            bytes | None:
                The PDF document or None in case of an error (e.g. no output form configured).

        """

        # GetPDF is a function import that is called with GET (the parameters are in the query string):
        response = self.do_request(
            url=self.service_url("API_BILLING_DOCUMENT_SRV") + "/GetPDF",
            params={"BillingDocument": odata_literal(billing_document_id)},
            failure_message="Failed to get the PDF of SAP billing document -> '{}'".format(billing_document_id),
        )
        if response is None:
            return None

        data = response.get("d", response)
        content = data.get("GetPDF", data).get("BillingDocumentBinary")
        if not content:
            self.log_error("SAP returned no PDF for billing document -> '%s'", billing_document_id)
            return None

        return base64.b64decode(content)

    # end method definition

    def create_outbound_delivery(self, delivery: SAPOutboundDeliveryModel | dict) -> dict | None:
        """Create an SAP outbound delivery for sales order items.

        Uses the OData V2 API API_OUTBOUND_DELIVERY_SRV (version 0002) with a deep insert.
        Material, plant and customer are copied from the sales order.

        Args:
            delivery (SAPOutboundDeliveryModel | dict):
                The data. A dictionary is validated against the SAPOutboundDeliveryModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created delivery as returned by SAP (including the number in "DeliveryDocument")
                or None in case of an error.

        Example:
            >>> sap.create_outbound_delivery(
            ...     {"shipping_point": "1010", "items": [{"reference_document": "413", "reference_document_item": "10"}]}
            ... )

        """

        return self._create_odata_entity(
            service="API_OUTBOUND_DELIVERY_SRV",
            entity_set="A_OutbDeliveryHeader",
            model=SAPOutboundDeliveryModel,
            data=delivery,
            key_fields=["DeliveryDocument"],
            label="outbound delivery",
        )

    # end method definition

    def iter_outbound_deliveries(
        self, query: SAPOutboundDeliveryQueryModel | None = None
    ) -> SAPODataIterator[SAPOutboundDeliveryResponseModel]:
        """Iterate over SAP outbound deliveries - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPOutboundDeliveryQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all deliveries).

        Returns:
            SAPODataIterator[SAPOutboundDeliveryResponseModel]:
                The iterator over the outbound deliveries.

        """

        query = query or SAPOutboundDeliveryQueryModel()

        if query.has_item_criteria:
            # A_OutbDeliveryHeader cannot be filtered by its items (OData V2 has no any()) - find the
            # deliveries of the sales orders / materials via their items, then read them by their IDs:
            items = self.iter_outbound_delivery_items(
                query=SAPOutboundDeliveryItemQueryModel(
                    sales_orders=query.sales_orders, materials=query.materials, delivery_ids=query.delivery_ids
                )
            )
            delivery_ids = list(dict.fromkeys(item.delivery_id for item in items if item.delivery_id))
            if items.failed:
                return SAPODataIterator(_failed_odata_read())
            if not delivery_ids:
                self.logger.info(
                    "No SAP outbound deliveries for sales orders -> %s / materials -> %s.",
                    str(query.sales_orders),
                    str(query.materials),
                )
                return SAPODataIterator(iter([]))
            query = query.model_copy(update={"delivery_ids": delivery_ids, "sales_orders": None, "materials": None})

        return self._iter_odata_collection(
            service="API_OUTBOUND_DELIVERY_SRV",
            entity_set="A_OutbDeliveryHeader",
            model=SAPOutboundDeliveryResponseModel,
            query=query,
            label="outbound deliveries",
        )

    # end method definition

    def iter_outbound_delivery_items(
        self, query: SAPOutboundDeliveryItemQueryModel | None = None
    ) -> SAPODataIterator[SAPOutboundDeliveryItemResponseModel]:
        """Iterate over SAP outbound delivery items - reading them page by page.

        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPOutboundDeliveryItemQueryModel | None, optional):
                The search criteria, e.g. the sales orders of the items. Defaults to None (all items).

        Returns:
            SAPODataIterator[SAPOutboundDeliveryItemResponseModel]:
                The iterator over the delivery items.

        """

        return self._iter_odata_collection(
            service="API_OUTBOUND_DELIVERY_SRV",
            entity_set="A_OutbDeliveryItem",
            model=SAPOutboundDeliveryItemResponseModel,
            query=query or SAPOutboundDeliveryItemQueryModel(),
            label="outbound delivery items",
        )

    # end method definition

    def get_outbound_deliveries(
        self, query: SAPOutboundDeliveryQueryModel | None = None
    ) -> list[SAPOutboundDeliveryResponseModel] | None:
        """Get SAP outbound deliveries as a list.

        All matching deliveries are read (page by page, see iter_outbound_deliveries()) and returned at once.
        For very large result sets prefer iter_outbound_deliveries().

        Args:
            query (SAPOutboundDeliveryQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all deliveries).

        Returns:
            list[SAPOutboundDeliveryResponseModel] | None:
                The outbound deliveries (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_outbound_deliveries(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP outbound deliveries.", len(results))

        return results

    # end method definition

    def get_outbound_delivery(
        self, delivery_id: str, expand_items: bool = True
    ) -> SAPOutboundDeliveryResponseModel | None:
        """Get a single SAP outbound delivery.

        Args:
            delivery_id (str):
                The delivery number, e.g. "80000123".
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPOutboundDeliveryResponseModel | None:
                The outbound delivery or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_OUTBOUND_DELIVERY_SRV",
            entity_path="A_OutbDeliveryHeader('{}')".format(self._quote_key(delivery_id)),
            model=SAPOutboundDeliveryResponseModel,
            params={"$expand": "to_DeliveryDocumentItem"} if expand_items else None,
            label="outbound delivery -> '{}'".format(delivery_id),
        )

    # end method definition

    def update_outbound_delivery(
        self, delivery_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP outbound delivery and of its items.

        All changes are validated first and the items must belong to the outbound delivery - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        SAP allows to change e.g. the storage location (required for the goods issue), the batch or
        the delivery quantity of the items - items can also be referred to by their material.

        Args:
            delivery_id (str):
                The outbound delivery number, e.g. "80000123".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPOutboundDeliveryModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"10": {"StorageLocation": "0001"}} (snake case attribute names of SAPOutboundDeliveryItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the outbound delivery (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(delivery_id)

        return self._update_odata_document(
            service="API_OUTBOUND_DELIVERY_SRV",
            label="outbound delivery -> '{}'".format(delivery_id),
            header_path="A_OutbDeliveryHeader('{}')".format(key),
            header_model=SAPOutboundDeliveryModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="A_OutbDeliveryHeader('{}')/to_DeliveryDocumentItem".format(key),
                entity_set="A_OutbDeliveryItem",
                key_properties=("DeliveryDocument", "DeliveryDocumentItem"),
                number_property="DeliveryDocumentItem",
                text_property="Material",
                label="item",
            ),
            item_model=SAPOutboundDeliveryItemModel,
        )

    # end method definition

    def delete_outbound_delivery(self, delivery_id: str) -> bool:
        """Delete an SAP outbound delivery (only possible before the goods issue).

        Args:
            delivery_id (str):
                The delivery number, e.g. "80000123".

        Returns:
            bool:
                True if the delivery has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_OUTBOUND_DELIVERY_SRV",
            entity_path="A_OutbDeliveryHeader('{}')".format(self._quote_key(delivery_id)),
            label="outbound delivery -> '{}'".format(delivery_id),
        )

    # end method definition

    def change_outbound_delivery_status(
        self,
        delivery_id: str,
        action: SAPOutboundDeliveryAction | str,
        parameters: dict | None = None,
    ) -> bool:
        """Change the status of an SAP outbound delivery (e.g. pick all items or post the goods issue).

        The delivery functions require the current ETag of the delivery (If-Match header),
        so the delivery is read first.

        Args:
            delivery_id (str):
                The delivery number, e.g. "80000123".
            action (SAPOutboundDeliveryAction | str):
                The status action, e.g. SAPOutboundDeliveryAction.POST_GOODS_ISSUE - or the name of
                another function of the API, e.g. "PickOneItem".
            parameters (dict | None, optional):
                Additional parameters of the action with their OData names, e.g.
                {"ActualGoodsMovementDate": date(2026, 11, 2)} for ReverseGoodsIssue or
                {"DeliveryDocumentItem": "000010"} for item actions. Defaults to None.

        Returns:
            bool:
                True if the status has been changed, False in case of an error.

        """

        label = "{} outbound delivery -> '{}'".format(str(action), delivery_id)
        headers = {}
        exists, etag = self._get_odata_etag(
            url=self.service_url("API_OUTBOUND_DELIVERY_SRV")
            + "/A_OutbDeliveryHeader('{}')".format(self._quote_key(delivery_id)),
            headers=headers,
            label="outbound delivery -> '{}'".format(delivery_id),
        )
        if not exists:
            return False
        headers["If-Match"] = etag or "*"
        params = {
            name: odata_literal(value)
            for name, value in {"DeliveryDocument": delivery_id, **(parameters or {})}.items()
            if value is not None
        }

        self.logger.info("Call SAP function -> '%s' to %s...", str(action), label)
        response = self.do_request(
            url=self.service_url("API_OUTBOUND_DELIVERY_SRV") + "/" + str(action),
            method="POST",
            headers=headers,
            params=params,
            failure_message="Failed to {}".format(label),
            success_message="Successfully completed: {}.".format(label),
        )

        return response is not None

    # end method definition

    def create_inbound_delivery(self, delivery: SAPInboundDeliveryModel | dict) -> dict | None:
        """Create an SAP inbound delivery for purchase order items.

        Uses the OData V2 API API_INBOUND_DELIVERY_SRV (version 0002) with a deep insert.

        Args:
            delivery (SAPInboundDeliveryModel | dict):
                The data. A dictionary is validated against the SAPInboundDeliveryModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created delivery as returned by SAP (including the number in "DeliveryDocument")
                or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_INBOUND_DELIVERY_SRV",
            entity_set="A_InbDeliveryHeader",
            model=SAPInboundDeliveryModel,
            data=delivery,
            key_fields=["DeliveryDocument"],
            label="inbound delivery",
        )

    # end method definition

    def iter_inbound_deliveries(
        self, query: SAPInboundDeliveryQueryModel | None = None
    ) -> SAPODataIterator[SAPInboundDeliveryResponseModel]:
        """Iterate over SAP inbound deliveries - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPInboundDeliveryQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all deliveries).

        Returns:
            SAPODataIterator[SAPInboundDeliveryResponseModel]:
                The iterator over the inbound deliveries.

        """

        query = query or SAPInboundDeliveryQueryModel()

        if query.has_item_criteria:
            # A_InbDeliveryHeader cannot be filtered by its items (OData V2 has no any()) - find the
            # deliveries of the purchase orders / materials via their items, then read them by their IDs:
            items = self.iter_inbound_delivery_items(
                query=SAPInboundDeliveryItemQueryModel(
                    purchase_orders=query.purchase_orders, materials=query.materials, delivery_ids=query.delivery_ids
                )
            )
            delivery_ids = list(dict.fromkeys(item.delivery_id for item in items if item.delivery_id))
            if items.failed:
                return SAPODataIterator(_failed_odata_read())
            if not delivery_ids:
                self.logger.info(
                    "No SAP inbound deliveries for purchase orders -> %s / materials -> %s.",
                    str(query.purchase_orders),
                    str(query.materials),
                )
                return SAPODataIterator(iter([]))
            query = query.model_copy(update={"delivery_ids": delivery_ids, "purchase_orders": None, "materials": None})

        return self._iter_odata_collection(
            service="API_INBOUND_DELIVERY_SRV",
            entity_set="A_InbDeliveryHeader",
            model=SAPInboundDeliveryResponseModel,
            query=query,
            label="inbound deliveries",
        )

    # end method definition

    def iter_inbound_delivery_items(
        self, query: SAPInboundDeliveryItemQueryModel | None = None
    ) -> SAPODataIterator[SAPInboundDeliveryItemResponseModel]:
        """Iterate over SAP inbound delivery items - reading them page by page.

        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPInboundDeliveryItemQueryModel | None, optional):
                The search criteria, e.g. the purchase orders of the items. Defaults to None (all items).

        Returns:
            SAPODataIterator[SAPInboundDeliveryItemResponseModel]:
                The iterator over the delivery items.

        """

        return self._iter_odata_collection(
            service="API_INBOUND_DELIVERY_SRV",
            entity_set="A_InbDeliveryItem",
            model=SAPInboundDeliveryItemResponseModel,
            query=query or SAPInboundDeliveryItemQueryModel(),
            label="inbound delivery items",
        )

    # end method definition

    def get_inbound_deliveries(
        self, query: SAPInboundDeliveryQueryModel | None = None
    ) -> list[SAPInboundDeliveryResponseModel] | None:
        """Get SAP inbound deliveries as a list.

        All matching deliveries are read (page by page, see iter_inbound_deliveries()) and returned at once.
        For very large result sets prefer iter_inbound_deliveries().

        Args:
            query (SAPInboundDeliveryQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all deliveries).

        Returns:
            list[SAPInboundDeliveryResponseModel] | None:
                The inbound deliveries (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_inbound_deliveries(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP inbound deliveries.", len(results))

        return results

    # end method definition

    def get_inbound_delivery(
        self, delivery_id: str, expand_items: bool = True
    ) -> SAPInboundDeliveryResponseModel | None:
        """Get a single SAP inbound delivery.

        Args:
            delivery_id (str):
                The delivery number, e.g. "180000123".
            expand_items (bool, optional):
                Whether to read the items as well. Defaults to True.

        Returns:
            SAPInboundDeliveryResponseModel | None:
                The inbound delivery or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_INBOUND_DELIVERY_SRV",
            entity_path="A_InbDeliveryHeader('{}')".format(self._quote_key(delivery_id)),
            model=SAPInboundDeliveryResponseModel,
            params={"$expand": "to_DeliveryDocumentItem"} if expand_items else None,
            label="inbound delivery -> '{}'".format(delivery_id),
        )

    # end method definition

    def update_inbound_delivery(
        self, delivery_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP inbound delivery and of its items.

        All changes are validated first and the items must belong to the inbound delivery - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        SAP allows to change e.g. the delivered quantity or the batch of the items (not their storage
        location) - items can also be referred to by their material.

        Args:
            delivery_id (str):
                The inbound delivery number, e.g. "180000123".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPInboundDeliveryModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"10": {"ActualDeliveryQuantity": 4}} (snake case attribute names of SAPInboundDeliveryItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the inbound delivery (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(delivery_id)

        return self._update_odata_document(
            service="API_INBOUND_DELIVERY_SRV",
            label="inbound delivery -> '{}'".format(delivery_id),
            header_path="A_InbDeliveryHeader('{}')".format(key),
            header_model=SAPInboundDeliveryModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="A_InbDeliveryHeader('{}')/to_DeliveryDocumentItem".format(key),
                entity_set="A_InbDeliveryItem",
                key_properties=("DeliveryDocument", "DeliveryDocumentItem"),
                number_property="DeliveryDocumentItem",
                text_property="Material",
                label="item",
            ),
            item_model=SAPInboundDeliveryItemModel,
        )

    # end method definition

    def delete_inbound_delivery(self, delivery_id: str) -> bool:
        """Delete an SAP inbound delivery (only possible before the goods receipt).

        Args:
            delivery_id (str):
                The delivery number, e.g. "180000123".

        Returns:
            bool:
                True if the delivery has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_INBOUND_DELIVERY_SRV",
            entity_path="A_InbDeliveryHeader('{}')".format(self._quote_key(delivery_id)),
            label="inbound delivery -> '{}'".format(delivery_id),
        )

    # end method definition

    def change_inbound_delivery_status(
        self,
        delivery_id: str,
        action: SAPInboundDeliveryAction | str,
        parameters: dict | None = None,
    ) -> bool:
        """Change the status of an SAP inbound delivery (e.g. put away all items or post the goods receipt).

        The delivery functions require the current ETag of the delivery (If-Match header),
        so the delivery is read first.

        Args:
            delivery_id (str):
                The delivery number, e.g. "180000123".
            action (SAPInboundDeliveryAction | str):
                The status action, e.g. SAPInboundDeliveryAction.POST_GOODS_RECEIPT - or the name of
                another function of the API, e.g. "PutawayOneItem".
            parameters (dict | None, optional):
                Additional parameters of the action with their OData names, e.g.
                {"ActualGoodsMovementDate": date(2026, 11, 2)} for ReverseGoodsReceipt or
                {"DeliveryDocumentItem": "000010"} for item actions. Defaults to None.

        Returns:
            bool:
                True if the status has been changed, False in case of an error.

        """

        label = "{} inbound delivery -> '{}'".format(str(action), delivery_id)
        headers = {}
        exists, etag = self._get_odata_etag(
            url=self.service_url("API_INBOUND_DELIVERY_SRV")
            + "/A_InbDeliveryHeader('{}')".format(self._quote_key(delivery_id)),
            headers=headers,
            label="inbound delivery -> '{}'".format(delivery_id),
        )
        if not exists:
            return False
        headers["If-Match"] = etag or "*"
        params = {
            name: odata_literal(value)
            for name, value in {"DeliveryDocument": delivery_id, **(parameters or {})}.items()
            if value is not None
        }

        self.logger.info("Call SAP function -> '%s' to %s...", str(action), label)
        response = self.do_request(
            url=self.service_url("API_INBOUND_DELIVERY_SRV") + "/" + str(action),
            method="POST",
            headers=headers,
            params=params,
            failure_message="Failed to {}".format(label),
            success_message="Successfully completed: {}.".format(label),
        )

        return response is not None

    # end method definition

    def create_supplier_invoice(self, invoice: SAPSupplierInvoiceModel | dict) -> dict | None:
        """Create (post or park) an SAP supplier invoice including its items.

        Uses the OData V2 API API_SUPPLIERINVOICE_PROCESS_SRV with a deep insert (logistics
        invoice verification, like transaction MIRO). The invoice is posted directly unless it
        is parked (status "A") - a parked invoice is posted with post_supplier_invoice() or
        deleted with delete_supplier_invoice().

        Args:
            invoice (SAPSupplierInvoiceModel | dict):
                The data. A dictionary is validated against the SAPSupplierInvoiceModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created invoice as returned by SAP (including "SupplierInvoice" and "FiscalYear")
                or None in case of an error.

        Example:
            >>> sap.create_supplier_invoice(
            ... {
            ...     "company_code": "1010",
            ...     "document_date": "2026-11-02",
            ...     "posting_date": "2026-11-02",
            ...     "supplier_invoice_reference": "INV-2026-0815",
            ...     "currency": "EUR",
            ...     "gross_amount": "297.50",
            ...     "tax_is_calculated_automatically": True,
            ...     "purchase_order_items": [
            ...         {"purchase_order": "4500001540", "purchase_order_item": "10", "amount": "250", "tax_code": "V1"},
            ...     ],
            ... }
            ... )

        """

        return self._create_odata_entity(
            service="API_SUPPLIERINVOICE_PROCESS_SRV",
            entity_set="A_SupplierInvoice",
            model=SAPSupplierInvoiceModel,
            data=invoice,
            key_fields=["SupplierInvoice", "FiscalYear"],
            label="supplier invoice",
        )

    # end method definition

    def iter_supplier_invoices(
        self, query: SAPSupplierInvoiceQueryModel | None = None
    ) -> SAPODataIterator[SAPSupplierInvoiceResponseModel]:
        """Iterate over SAP supplier invoices - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPSupplierInvoiceQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all invoices).

        Returns:
            SAPODataIterator[SAPSupplierInvoiceResponseModel]:
                The iterator over the supplier invoices.

        """

        return self._iter_odata_collection(
            service="API_SUPPLIERINVOICE_PROCESS_SRV",
            entity_set="A_SupplierInvoice",
            model=SAPSupplierInvoiceResponseModel,
            query=query or SAPSupplierInvoiceQueryModel(),
            label="supplier invoices",
        )

    # end method definition

    def get_supplier_invoices(
        self, query: SAPSupplierInvoiceQueryModel | None = None
    ) -> list[SAPSupplierInvoiceResponseModel] | None:
        """Get SAP supplier invoices as a list.

        All matching invoices are read (page by page, see iter_supplier_invoices()) and returned at once.
        For very large result sets prefer iter_supplier_invoices().

        Args:
            query (SAPSupplierInvoiceQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all invoices).

        Returns:
            list[SAPSupplierInvoiceResponseModel] | None:
                The supplier invoices (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_supplier_invoices(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP supplier invoices.", len(results))

        return results

    # end method definition

    def get_supplier_invoice(
        self, invoice_id: str, fiscal_year: str, expand_items: bool = True
    ) -> SAPSupplierInvoiceResponseModel | None:
        """Get a single SAP supplier invoice.

        Args:
            invoice_id (str):
                The supplier invoice number, e.g. "5105600123".
            fiscal_year (str):
                The fiscal year of the invoice, e.g. "2026".
            expand_items (bool, optional):
                Whether to read the purchase order and G/L account items as well. Defaults to True.

        Returns:
            SAPSupplierInvoiceResponseModel | None:
                The supplier invoice or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_SUPPLIERINVOICE_PROCESS_SRV",
            entity_path="A_SupplierInvoice(SupplierInvoice='{}',FiscalYear='{}')".format(
                self._quote_key(invoice_id), self._quote_key(fiscal_year)
            ),
            model=SAPSupplierInvoiceResponseModel,
            params={"$expand": SAPSupplierInvoiceQueryModel.EXPAND} if expand_items else None,
            label="supplier invoice -> {}/{}".format(invoice_id, fiscal_year),
        )

    # end method definition

    def delete_supplier_invoice(self, invoice_id: str, fiscal_year: str) -> bool:
        """Delete an SAP supplier invoice - only parked or held invoices; posted ones are cancelled instead.

        Args:
            invoice_id (str):
                The supplier invoice number, e.g. "5105600123".
            fiscal_year (str):
                The fiscal year of the invoice, e.g. "2026".

        Returns:
            bool:
                True if the invoice has been deleted, False in case of an error.

        """

        return self._delete_odata_entity(
            service="API_SUPPLIERINVOICE_PROCESS_SRV",
            entity_path="A_SupplierInvoice(SupplierInvoice='{}',FiscalYear='{}')".format(
                self._quote_key(invoice_id), self._quote_key(fiscal_year)
            ),
            label="supplier invoice -> {}/{}".format(invoice_id, fiscal_year),
        )

    # end method definition

    def cancel_supplier_invoice(
        self,
        invoice_id: str,
        fiscal_year: str,
        reversal_reason: str = "01",
        posting_date: date | None = None,
    ) -> dict | None:
        """Cancel (reverse) a posted SAP supplier invoice - SAP posts a reversal document.

        Args:
            invoice_id (str):
                The supplier invoice number, e.g. "5105600123".
            fiscal_year (str):
                The fiscal year of the invoice, e.g. "2026".
            reversal_reason (str, optional):
                The reversal reason, e.g. "01" (reversal in current period, default) or "02"
                (reversal in closed period) - system specific.
            posting_date (date | None, optional):
                The posting date of the reversal. Defaults to None (today).

        Returns:
            dict | None:
                The result (including the reversal document in "ReverseDocument" and "FiscalYear")
                or None in case of an error.

        """

        result = self._call_odata_function(
            service="API_SUPPLIERINVOICE_PROCESS_SRV",
            function="Cancel",
            parameters={
                "SupplierInvoice": invoice_id,
                "FiscalYear": fiscal_year,
                "ReversalReason": reversal_reason,
                "PostingDate": posting_date or datetime.now(tz=UTC).date(),
            },
            label="cancel supplier invoice -> {}/{}".format(invoice_id, fiscal_year),
        )
        if result is None:
            return None

        result = result.get("Cancel", result)
        if result.get("Success") is False or not result.get("ReverseDocument"):
            self.log_error(
                "SAP did not cancel the supplier invoice -> %s/%s; result -> %s", invoice_id, fiscal_year, str(result)
            )
            return None

        return result

    # end method definition

    def release_supplier_invoice(self, invoice_id: str, fiscal_year: str, shift_discount_days: bool = False) -> bool:
        """Release an SAP supplier invoice that is blocked for payment.

        Args:
            invoice_id (str):
                The supplier invoice number, e.g. "5105600123".
            fiscal_year (str):
                The fiscal year of the invoice, e.g. "2026".
            shift_discount_days (bool, optional):
                Whether the cash discount days are shifted by the time the invoice was blocked. Defaults to False.

        Returns:
            bool:
                True if the invoice has been released, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_SUPPLIERINVOICE_PROCESS_SRV",
            function="Release",
            parameters={
                "SupplierInvoice": invoice_id,
                "FiscalYear": fiscal_year,
                "DiscountDaysHaveToBeShifted": shift_discount_days,
            },
            label="release supplier invoice -> {}/{}".format(invoice_id, fiscal_year),
        )
        if result is None:
            return False

        if result.get("Release", result).get("Success") is False:
            self.log_error("SAP did not release the supplier invoice -> %s/%s", invoice_id, fiscal_year)
            return False

        return True

    # end method definition

    def post_supplier_invoice(self, invoice_id: str, fiscal_year: str) -> bool:
        """Post a parked SAP supplier invoice (see SAPSupplierInvoiceModel.status).

        Args:
            invoice_id (str):
                The supplier invoice number, e.g. "5105600123".
            fiscal_year (str):
                The fiscal year of the invoice, e.g. "2026".

        Returns:
            bool:
                True if the invoice has been posted, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_SUPPLIERINVOICE_PROCESS_SRV",
            function="Post",
            parameters={"SupplierInvoice": invoice_id, "FiscalYear": fiscal_year},
            label="post supplier invoice -> {}/{}".format(invoice_id, fiscal_year),
        )
        if result is None:
            return False

        if result.get("Post", result).get("Success") is False:
            self.log_error("SAP did not post the supplier invoice -> %s/%s", invoice_id, fiscal_year)
            return False

        return True

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

        query = query or SAPGoodsMovementQueryModel()
        keys = None

        if query.has_item_criteria:
            # A_MaterialDocumentHeader cannot be filtered by its items (OData V2 has no any()) - find the
            # material documents via their items, then read them by their keys (number and year):
            item_criteria = {
                "purchase_orders": query.purchase_orders,
                "production_orders": query.production_orders,
                "materials": query.materials,
                "plants": query.plants,
                "movement_types": query.movement_types,
            }
            items = self.iter_goods_movement_items(
                query=SAPGoodsMovementItemQueryModel(
                    **item_criteria, document_year=query.document_year, documents=query.documents
                )
            )
            keys = list(dict.fromkeys((item.document, item.document_year) for item in items))
            if items.failed:
                return SAPODataIterator(_failed_odata_read())
            if not keys:
                self.logger.info(
                    "No SAP material documents with items matching -> %s.",
                    str({name: value for name, value in item_criteria.items() if value}),
                )
                return SAPODataIterator(iter([]))
            years = {year for _, year in keys}
            query = query.model_copy(
                update={
                    "documents": list(dict.fromkeys(document for document, _ in keys)),
                    "document_year": years.pop() if len(years) == 1 else query.document_year,
                }
                | dict.fromkeys(item_criteria)
            )

        movements = self._iter_odata_collection(
            service="API_MATERIAL_DOCUMENT_SRV",
            entity_set="A_MaterialDocumentHeader",
            model=SAPGoodsMovementResponseModel,
            query=query,
            label="goods movements",
        )
        if keys is None or query.document_year:
            return movements

        # Material document numbers are only unique per year - with matches in several years, the
        # headers are read by number and only the documents of the matching (number, year) pairs kept:
        wanted = set(keys)

        def matching_movements() -> Iterator[SAPGoodsMovementResponseModel]:
            for movement in movements:
                if (movement.document, movement.document_year) in wanted:
                    yield movement
            if movements.failed:
                raise _ODataReadError

        return SAPODataIterator(matching_movements())

    # end method definition

    def iter_goods_movement_items(
        self, query: SAPGoodsMovementItemQueryModel | None = None
    ) -> SAPODataIterator[SAPGoodsMovementItemResponseModel]:
        """Iterate over SAP material document items - reading them page by page.

        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPGoodsMovementItemQueryModel | None, optional):
                The search criteria, e.g. the purchase orders of the items. Defaults to None (all items).

        Returns:
            SAPODataIterator[SAPGoodsMovementItemResponseModel]:
                The iterator over the material document items.

        """

        return self._iter_odata_collection(
            service="API_MATERIAL_DOCUMENT_SRV",
            entity_set="A_MaterialDocumentItem",
            model=SAPGoodsMovementItemResponseModel,
            query=query or SAPGoodsMovementItemQueryModel(),
            label="material document items",
        )

    # end method definition

    def get_goods_movement_items(
        self, query: SAPGoodsMovementItemQueryModel | None = None
    ) -> list[SAPGoodsMovementItemResponseModel] | None:
        """Get SAP material document items as a list.

        All matching items are read (page by page, see iter_goods_movement_items()) and returned at once.

        Args:
            query (SAPGoodsMovementItemQueryModel | None, optional):
                The search criteria, e.g. the purchase orders and movement types of the items.
                Defaults to None (all items).

        Returns:
            list[SAPGoodsMovementItemResponseModel] | None:
                The material document items (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_goods_movement_items(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP material document items.", len(results))

        return results

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

    def iter_material_stock(
        self, query: SAPMaterialStockQueryModel | None = None
    ) -> SAPODataIterator[SAPMaterialStockResponseModel]:
        """Iterate over the SAP material stock - reading it page by page from SAP.

        Each entry is the stock of a material in one stock segment (plant, storage location,
        batch, stock type and special stock). Use this for large result sets: only one page is
        held in memory at a time. Errors are logged and end the iteration (check the 'failed'
        attribute of the returned iterator afterwards).

        Args:
            query (SAPMaterialStockQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all stock
                except segments with a quantity of 0).

        Returns:
            SAPODataIterator[SAPMaterialStockResponseModel]:
                The iterator over the stock segments.

        """

        return self._iter_odata_collection(
            service="API_MATERIAL_STOCK_SRV",
            entity_set="A_MatlStkInAcctMod",
            model=SAPMaterialStockResponseModel,
            query=query or SAPMaterialStockQueryModel(),
            label="material stock",
        )

    # end method definition

    def get_material_stock(
        self, query: SAPMaterialStockQueryModel | None = None
    ) -> list[SAPMaterialStockResponseModel] | None:
        """Get the SAP material stock as a list of stock segments.

        All matching stock segments are read (page by page, see iter_material_stock()) and returned
        at once. For very large result sets prefer iter_material_stock().

        Args:
            query (SAPMaterialStockQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all stock
                except segments with a quantity of 0).

        Returns:
            list[SAPMaterialStockResponseModel] | None:
                The stock segments (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_material_stock(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP material stock segments.", len(results))

        return results

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
                The planning plants, functional locations and equipments (item properties) are
                resolved via the maintenance items first.

        Returns:
            SAPODataIterator[SAPMaintenancePlanResponseModel]:
                The iterator over the maintenance plans.

        """

        query = query or SAPMaintenancePlanQueryModel()

        if query.has_item_criteria:
            # MaintenancePlan cannot be filtered by its items (OData V2 has no any()) - find the
            # maintenance plans via their items, then read them by their IDs:
            item_criteria = {
                "planning_plants": query.planning_plants,
                "functional_location_ids": query.functional_location_ids,
                "functional_location_labels": query.functional_location_labels,
                "equipment_ids": query.equipment_ids,
            }
            items = self.iter_maintenance_plan_items(
                query=SAPMaintenancePlanItemQueryModel(**item_criteria, plan_ids=query.plan_ids)
            )
            plan_ids = list(dict.fromkeys(item.plan_id for item in items if item.plan_id))
            if items.failed:
                return SAPODataIterator(_failed_odata_read())
            if not plan_ids:
                self.logger.info(
                    "No SAP maintenance plans with items matching -> %s.",
                    str({name: value for name, value in item_criteria.items() if value}),
                )
                return SAPODataIterator(iter([]))
            query = query.model_copy(update={"plan_ids": plan_ids} | dict.fromkeys(item_criteria))

        return self._iter_odata_collection(
            service="API_MAINTENANCEPLAN",
            entity_set="MaintenancePlan",
            model=SAPMaintenancePlanResponseModel,
            query=query,
            label="maintenance plans",
        )

    # end method definition

    def iter_maintenance_plan_items(
        self, query: SAPMaintenancePlanItemQueryModel | None = None
    ) -> SAPODataIterator[SAPMaintenancePlanItemResponseModel]:
        """Iterate over SAP maintenance items (of maintenance plans) - reading them page by page.

        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPMaintenancePlanItemQueryModel | None, optional):
                The search criteria, e.g. the planning plants of the items.
                Defaults to None (all maintenance items).

        Returns:
            SAPODataIterator[SAPMaintenancePlanItemResponseModel]:
                The iterator over the maintenance items.

        """

        return self._iter_odata_collection(
            service="API_MAINTENANCEPLAN",
            entity_set="MaintenanceItem",
            model=SAPMaintenancePlanItemResponseModel,
            query=query or SAPMaintenancePlanItemQueryModel(),
            label="maintenance items",
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

    def update_maintenance_plan(
        self, plan_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP maintenance plan and of its items.

        All changes are validated first and the items must belong to the maintenance plan - otherwise
        nothing is changed. The items are changed first, the header last (see _update_odata_document()).

        The item numbers (MaintenanceItem) are unique in the SAP system, not positions in the plan.
        Cycles cannot be changed with this method.

        Args:
            plan_id (str):
                The maintenance plan number, e.g. "2".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPMaintenancePlanModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number, e.g. {"142": {"functional_location": "CW"}} (snake case attribute names of SAPMaintenancePlanItemModel or OData property names).
                Defaults to None (items unchanged).

        Returns:
            bool:
                True if the maintenance plan (and its items) have been updated, False in case of an error.

        """

        key = self._quote_key(plan_id)

        return self._update_odata_document(
            service="API_MAINTENANCEPLAN",
            label="maintenance plan -> '{}'".format(plan_id),
            header_path="MaintenancePlan('{}')".format(key),
            header_model=SAPMaintenancePlanModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="MaintenancePlan('{}')/to_Item".format(key),
                entity_set="MaintenanceItem",
                key_properties=("MaintenanceItem",),
                number_property="MaintenanceItem",
                text_property="MaintenanceItemDescription",
                label="item",
            ),
            item_model=SAPMaintenancePlanItemModel,
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
            # RAP based service - its functions need the ETag of the plan (428 Precondition required otherwise):
            etag_entity_path="MaintenancePlan('{}')".format(self._quote_key(plan_id)),
        )

        return result is not None

    # end method definition

    def create_task_list(self, task_list: SAPTaskListModel | dict) -> dict | None:
        """Create an SAP maintenance task list including its operations.

        Uses the OData V4 API API_MAINTENANCETASKLIST with a deep create, so the whole task list
        is created (and committed) in one request.

        Args:
            task_list (SAPTaskListModel | dict):
                The data. A dictionary is validated against the SAPTaskListModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created task list as returned by SAP (including "TaskListGroup" and
                "TaskListGroupCounter") or None in case of an error.

        Example:
            >>> sap.create_task_list(
            ... {
            ...     "task_list_type": "A",
            ...     "description": "Quarterly pump inspection",
            ...     "planning_plant": "1010",
            ...     "operations": [
            ...         {"description": "Check pump seal", "control_key": "PM01", "work": 2, "work_unit": "H"},
            ...     ],
            ... }
            ... )

        """

        return self._create_odata_entity(
            service="API_MAINTENANCETASKLIST",
            entity_set="MaintenanceTaskList",
            model=SAPTaskListModel,
            data=task_list,
            key_fields=["TaskListType", "TaskListGroup", "TaskListGroupCounter"],
            label="maintenance task list",
        )

    # end method definition

    def iter_task_lists(self, query: SAPTaskListQueryModel | None = None) -> SAPODataIterator[SAPTaskListResponseModel]:
        """Iterate over SAP maintenance task lists - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPTaskListQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all task lists).

        Returns:
            SAPODataIterator[SAPTaskListResponseModel]:
                The iterator over the task lists.

        """

        return self._iter_odata_collection(
            service="API_MAINTENANCETASKLIST",
            entity_set="MaintenanceTaskList",
            model=SAPTaskListResponseModel,
            query=query or SAPTaskListQueryModel(),
            label="maintenance task lists",
        )

    # end method definition

    def get_task_lists(self, query: SAPTaskListQueryModel | None = None) -> list[SAPTaskListResponseModel] | None:
        """Get SAP maintenance task lists as a list.

        All matching task lists are read (page by page, see iter_task_lists()) and returned at once.
        For very large result sets prefer iter_task_lists().

        Args:
            query (SAPTaskListQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all task lists).

        Returns:
            list[SAPTaskListResponseModel] | None:
                The task lists (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_task_lists(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP maintenance task lists.", len(results))

        return results

    # end method definition

    def get_task_list(
        self,
        task_list_type: str,
        task_list_group: str,
        task_list_group_counter: str,
        expand_items: bool = True,
    ) -> SAPTaskListResponseModel | None:
        """Get a single SAP maintenance task list.

        Task lists with change numbers can have several versions - the latest version is returned.

        Args:
            task_list_type (str):
                The task list type, e.g. "A" (general), "E" (equipment) or "T" (functional location).
            task_list_group (str):
                The task list group, e.g. "PUMP-01".
            task_list_group_counter (str):
                The task list group counter, e.g. "1".
            expand_items (bool, optional):
                Whether to read the operations as well. Defaults to True.

        Returns:
            SAPTaskListResponseModel | None:
                The task list or None if it does not exist or in case of an error.

        """

        # Sorted with the latest version first:
        entries = self.iter_task_lists(
            query=SAPTaskListQueryModel(
                task_list_types=[task_list_type],
                task_list_groups=[task_list_group],
                task_list_group_counters=[task_list_group_counter],
                expand_items=expand_items,
                limit=1,
            )
        )
        entry = next(entries, None)
        if entry is None and not entries.failed:
            self.logger.warning(
                "Cannot find SAP maintenance task list -> %s/%s/%s",
                task_list_type,
                task_list_group,
                task_list_group_counter,
            )

        return entry

    # end method definition

    def update_task_list(
        self,
        task_list_type: str,
        task_list_group: str,
        task_list_group_counter: str,
        changes: dict | None = None,
        item_changes: dict[str, dict] | None = None,
    ) -> bool:
        """Update individual fields of an SAP maintenance task list (its latest version) and of its operations.

        All changes are validated first and the operations must belong to the task list - otherwise
        nothing is changed. The operations are changed first, the header last (see _update_odata_document()).

        Args:
            task_list_type (str):
                The task list type, e.g. "A" (general), "E" (equipment) or "T" (functional location).
            task_list_group (str):
                The task list group, e.g. "PUMP-01".
            task_list_group_counter (str):
                The task list group counter, e.g. "1".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPTaskListModel or OData
                property names, e.g. {"description": "Monthly pump inspection"}. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per operation number, e.g. {"10": {"OperationText": "Replace seal"}} (snake case
                attribute names of SAPTaskListOperationModel or OData property names). Defaults to None
                (operations unchanged).

        Returns:
            bool:
                True if the task list (and its operations) have been updated, False in case of an error.

        """

        label = "maintenance task list -> {}/{}/{}".format(task_list_type, task_list_group, task_list_group_counter)
        header_path = None
        if changes:
            # The version counter is part of the key - read the latest version first:
            task_list = self.get_task_list(
                task_list_type=task_list_type,
                task_list_group=task_list_group,
                task_list_group_counter=task_list_group_counter,
                expand_items=False,
            )
            if task_list is None:
                return False
            header_path = (
                "MaintenanceTaskList(TaskListType='{}',TaskListGroup='{}',TaskListGroupCounter='{}',"
                "TaskListVersionCounter='{}')".format(
                    self._quote_key(task_list.task_list_type),
                    self._quote_key(task_list.task_list_group),
                    self._quote_key(task_list.task_list_group_counter),
                    self._quote_key(task_list.version_counter or ""),
                )
            )

        return self._update_odata_document(
            service="API_MAINTENANCETASKLIST",
            label=label,
            header_path=header_path,
            header_model=SAPTaskListModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="MaintenanceTaskListOperation",
                params={
                    "$filter": "TaskListType eq '{}' and TaskListGroup eq '{}' and TaskListGroupCounter eq '{}'".format(
                        self._quote_key(task_list_type),
                        self._quote_key(task_list_group),
                        self._quote_key(task_list_group_counter),
                    )
                },
                entity_set="MaintenanceTaskListOperation",
                key_properties=(
                    "TaskListType",
                    "TaskListGroup",
                    "TaskListGroupCounter",
                    "TaskListSequence",
                    "TaskListOperationInternalId",
                    "TaskListOpBOMItmIntVersCounter",
                ),
                number_property="MaintenanceTaskListOperation",
                text_property="OperationText",
                version_property="TaskListOpBOMItmIntVersCounter",
                label="operation",
            ),
            item_model=SAPTaskListOperationModel,
        )

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

    def update_planned_order(
        self, planned_order_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP planned order and of its components.

        All changes are validated first and the components must belong to the planned order - otherwise
        nothing is changed. The components are changed first, the header last (see _update_odata_document()).

        Like in SAP GUI (MD12), changing a component makes the planned order firm (PlannedOrderIsFirm,
        PlannedOrderBOMIsFixed) - MRP no longer changes it. The required quantity of a component cannot
        be changed (SAP ignores it) - it follows the planned order quantity and the bill of material.

        Args:
            planned_order_id (str):
                The planned order number, e.g. "103".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPPlannedOrderModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per component - BOM item number or material - e.g. {"0010": {"StorageLocation": "0001"}}
                or {"100-100": {"StorageLocation": "0001"}} (snake case attribute names of SAPPlannedOrderComponentModel
                or OData property names).
                Defaults to None (components unchanged).

        Returns:
            bool:
                True if the planned order (and its components) have been updated, False in case of an error.

        """

        key = self._quote_key(planned_order_id)

        return self._update_odata_document(
            service="API_PLANNEDORDER",
            label="planned order -> '{}'".format(planned_order_id),
            header_path="PlannedOrderHeader('{}')".format(key),
            header_model=SAPPlannedOrderModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="PlannedOrderComponent",
                params={"$filter": "PlannedOrder eq '{}'".format(key)},
                entity_set="PlannedOrderComponent",
                key_properties=("PlannedOrder", "Reservation", "ReservationItem"),
                number_property="BillOfMaterialItemNumber",
                text_property="Material",
                label="component",
            ),
            item_model=SAPPlannedOrderComponentModel,
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

    def create_production_order(
        self, order: SAPProductionOrderModel | dict, release: bool = False
    ) -> SAPProductionOrderResponseModel | None:
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
            SAPProductionOrderResponseModel | None:
                The production order as it is in SAP after the creation (and release) - read
                again, so the status shows whether the release was done (is_released) - or None
                in case of an error. If the release fails, the created order is still returned
                and last_error tells why it was not released. If it cannot be read again, the
                response of the creation is returned.

        """

        created = self._create_odata_entity(
            service="API_PRODUCTION_ORDER_2_SRV",
            entity_set="A_ProductionOrder_2",
            model=SAPProductionOrderModel,
            data=order,
            key_fields=["ManufacturingOrder"],
            label="production order",
        )
        if not created:
            return None

        order_id = created["ManufacturingOrder"]
        release_error = None
        if release and not self.change_production_order_status(order_id, SAPProductionOrderAction.RELEASE):
            release_error = self.last_error or "unknown error"

        # The response of the creation has the status before the release - read the order again:
        order = self.get_production_order(
            order_id=order_id, expand_items=True
        ) or SAPProductionOrderResponseModel.model_validate(created)

        # Set after reading the order (a successful request resets last_error):
        if release_error:
            self.log_error(
                "Production order -> '%s' has been created but could not be released; error -> %s",
                order_id,
                release_error,
            )

        return order

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

        # The conversion needs the ETag of the planned order (428 Precondition required otherwise). This
        # service has no entity set for planned orders - its ETag is the time stamp of the last change
        # (ABAP format YYYYMMDDhhmmss in UTC), read from API_PLANNEDORDER:
        planned_order = self.get_planned_order(planned_order_id=planned_order_id)
        if planned_order is None:
            if not self.last_error:
                self.log_error("Cannot convert SAP planned order -> '%s' - it does not exist!", planned_order_id)
            return None
        etag = (
            "W/\"'{}'\"".format(planned_order.last_change_datetime.astimezone(UTC).strftime("%Y%m%d%H%M%S"))
            if planned_order.last_change_datetime
            else None
        )

        result = self._call_odata_function(
            service="API_PRODUCTION_ORDER_2_SRV",
            function="ConvertPlndOrder",
            parameters={
                "PlannedOrder": planned_order_id,
                "ManufacturingOrderType": order_type,
                "ManufacturingOrder": production_order_id,
            },
            label="convert planned order -> '{}' into a production order".format(planned_order_id),
            etag=etag,
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

    def update_production_order(
        self, order_id: str, changes: dict | None = None, item_changes: dict[str, dict] | None = None
    ) -> bool:
        """Update individual fields of an SAP production order and of its operations.

        All changes are validated first and the operations must belong to the production order - otherwise
        nothing is changed. The operations are changed first, the header last (see _update_odata_document()).

        The item changes are changes of the operations (A_ProductionOrderOperation_2), e.g. their
        short text, work center, quantity or standard values.

        Args:
            order_id (str):
                The production order number, e.g. "1000185".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPProductionOrderModel or OData
                property names. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per operation number, e.g. {"0010": {"WorkCenter": "1320"}} (snake case attribute
                names of SAPProductionOrderOperationModel or OData property names).
                Defaults to None (operations unchanged).

        Returns:
            bool:
                True if the production order (and its operations) have been updated, False in case of an error.

        """

        # SAP only accepts standard values for operations with a work center - otherwise it fails with
        # "Input value ... for AFVGD-VGW01 could not be set" (verified in S/4HANA):
        standard_values = {"WorkCenterStandardWorkQty{}".format(number) for number in range(1, 7)}
        operations_to_check = []
        for operation, item_change in (item_changes or {}).items():
            try:
                payload = SAPProductionOrderOperationModel.to_odata_update(item_change)
            except ValueError:
                continue  # reported by _update_odata_document()
            if standard_values & payload.keys() and not payload.get("WorkCenter"):
                operations_to_check.append(str(operation).strip().lstrip("0"))
        if operations_to_check:
            order = self.get_production_order(order_id=order_id, expand_items=True)
            if order is None:
                return False
            without_work_center = {
                (operation.operation or "").lstrip("0")
                for operation in order.operations or []
                if not operation.work_center
            }
            if missing := [operation for operation in operations_to_check if operation in without_work_center]:
                self.log_error(
                    "Operation(s) -> %s of SAP production order -> '%s' have no work center - standard values can "
                    "only be set together with a work center (WorkCenter)!",
                    ", ".join(missing),
                    order_id,
                )
                return False

        key = self._quote_key(order_id)

        return self._update_odata_document(
            service="API_PRODUCTION_ORDER_2_SRV",
            label="production order -> '{}'".format(order_id),
            header_path="A_ProductionOrder_2('{}')".format(key),
            header_model=SAPProductionOrderModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path="A_ProductionOrder_2('{}')/to_ProductionOrderOperation".format(key),
                entity_set="A_ProductionOrderOperation_2",
                key_properties=("OrderInternalBillOfOperations", "OrderIntBillOfOperationsItem"),
                number_property="ManufacturingOrderOperation",
                text_property="MfgOrderOperationText",
                label="operation",
            ),
            item_model=SAPProductionOrderOperationModel,
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
            # The status functions need the ETag of the order (428 Precondition required otherwise):
            etag_entity_path="A_ProductionOrder_2('{}')".format(self._quote_key(order_id)),
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

    def create_product(self, product: SAPProductModel | dict) -> dict | None:
        """Create an SAP product / material with its descriptions and plant data.

        Args:
            product (SAPProductModel | dict):
                The data. A dictionary is validated against the SAPProductModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created product as returned by SAP (including "Product") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_PRODUCT_SRV",
            entity_set="A_Product",
            model=SAPProductModel,
            data=product,
            key_fields=["Product"],
            label="product",
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

        query, failed = self._resolve_text_search(
            service="API_PRODUCT_SRV", query=query or SAPProductQueryModel(), label="products"
        )
        if failed:
            return SAPODataIterator(_failed_odata_read())
        if query is None:
            return SAPODataIterator(iter([]))

        return self._iter_odata_collection(
            service="API_PRODUCT_SRV",
            entity_set="A_Product",
            model=SAPProductResponseModel,
            query=query,
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
                Whether to read the descriptions, plant data (with storage locations) and
                valuation data as well. Defaults to True.

        Returns:
            SAPProductResponseModel | None:
                The product or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_PRODUCT_SRV",
            entity_path="A_Product('{}')".format(self._quote_key(product_id)),
            model=SAPProductResponseModel,
            params={"$expand": "to_Description,to_Plant/to_StorageLocation,to_Valuation"} if expand_items else None,
            label="product -> '{}'".format(product_id),
        )

    # end method definition

    def update_product(self, product_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP product (material) on client level.

        The changes are validated with the field definitions of SAPProductModel (e.g. upper
        case codes, lengths). The product number and the product type cannot be changed.
        Descriptions and plant data are changed with update_product_description() and
        update_product_plant().

        Args:
            product_id (str):
                The product (material) number, e.g. "FG126".
            changes (dict):
                The fields to change - snake case attribute names of SAPProductModel or OData
                property names, e.g. {"product_group": "L001", "GrossWeight": "12.5"}.

        Returns:
            bool:
                True if the product has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_PRODUCT_SRV",
            entity_path="A_Product('{}')".format(self._quote_key(product_id)),
            model=SAPProductModel,
            changes=changes,
            label="product -> '{}'".format(product_id),
        )

    # end method definition

    def update_product_description(self, product_id: str, language: str, description: str) -> bool:
        """Change the description of an SAP product (material) in one language.

        Args:
            product_id (str):
                The product (material) number, e.g. "FG126".
            language (str):
                The language key of the (existing) description, e.g. "EN".
            description (str):
                The new description, e.g. "Pump seal 50 mm".

        Returns:
            bool:
                True if the description has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_PRODUCT_SRV",
            entity_path="A_ProductDescription(Product='{}',Language='{}')".format(
                self._quote_key(product_id), self._quote_key(language.upper())
            ),
            model=SAPProductDescriptionModel,
            changes={"description": description},
            label="description -> '{}' of product -> '{}'".format(language, product_id),
        )

    # end method definition

    def update_product_plant(self, product_id: str, plant: str, changes: dict) -> bool:
        """Update individual fields of the plant data of an SAP product (material).

        The product must already be extended to the plant. The changes are validated with the
        field definitions of SAPProductPlantModel.

        Changes of fields that belong to a view which is not maintained for the plant may be
        ignored by SAP without an error (e.g. the purchasing group without a purchasing view).
        Setting a field of another view can also add that view (e.g. the MRP view with the
        MRP type) - its required fields can then not be cleared any more.

        Args:
            product_id (str):
                The product (material) number, e.g. "FG126".
            plant (str):
                The plant, e.g. "1010".
            changes (dict):
                The fields to change - snake case attribute names of SAPProductPlantModel or OData
                property names, e.g. {"mrp_type": "PD", "purchasing_group": "001"}.

        Returns:
            bool:
                True if the plant data has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_PRODUCT_SRV",
            entity_path="A_ProductPlant(Product='{}',Plant='{}')".format(
                self._quote_key(product_id), self._quote_key(plant)
            ),
            model=SAPProductPlantModel,
            changes=changes,
            label="plant data -> '{}' of product -> '{}'".format(plant, product_id),
        )

    # end method definition

    def create_product_plant(self, product_id: str, plant: SAPProductPlantModel | dict) -> dict | None:
        """Extend an existing SAP product (material) to a plant - with its storage locations in the plant.

        Args:
            product_id (str):
                The product (material) number, e.g. "KT-4402".
            plant (SAPProductPlantModel | dict):
                The plant data (incl. storage locations). A dictionary is validated against the
                SAPProductPlantModel and can use either the snake case attribute names or the OData
                property names.

        Returns:
            dict | None:
                The created plant data as returned by SAP or None in case of an error.

        """

        if isinstance(plant, dict):
            try:
                plant = SAPProductPlantModel.model_validate(plant)
            except ValidationError as validation_error:
                self.log_error("Invalid plant data of product -> '%s'; error -> %s", product_id, str(validation_error))
                return None
        # The product is given by the URL - SAP needs it in the payload of the plant and its storage locations:
        plant = plant.model_copy(deep=True, update={"product_id": product_id})
        for storage_location in plant.storage_locations:
            storage_location.product_id = product_id
            storage_location.plant = plant.plant

        return self._create_odata_entity(
            service="API_PRODUCT_SRV",
            entity_set="A_Product('{}')/to_Plant".format(self._quote_key(product_id)),
            model=SAPProductPlantModel,
            data=plant,
            key_fields=["Plant"],
            label="plant data -> '{}' of product -> '{}'".format(plant.plant, product_id),
        )

    # end method definition

    def create_product_storage_location(
        self, product_id: str, plant: str, storage_location: SAPProductStorageLocationModel | dict
    ) -> dict | None:
        """Extend an SAP product (material) that is already extended to the plant to a storage location.

        Args:
            product_id (str):
                The product (material) number, e.g. "EP-300".
            plant (str):
                The plant the product is extended to, e.g. "3000".
            storage_location (SAPProductStorageLocationModel | dict):
                The storage location data, e.g. {"StorageLocation": "0001"}.

        Returns:
            dict | None:
                The created storage location data as returned by SAP or None in case of an error.

        """

        # The product and plant are given by the URL - SAP needs them in the payload as well (also for models):
        if isinstance(storage_location, dict):
            storage_location = {**storage_location, "Product": product_id, "Plant": plant}
        else:
            storage_location = storage_location.model_copy(update={"product_id": product_id, "plant": plant})

        return self._create_odata_entity(
            service="API_PRODUCT_SRV",
            entity_set="A_ProductPlant(Product='{}',Plant='{}')/to_StorageLocation".format(
                self._quote_key(product_id), self._quote_key(plant)
            ),
            model=SAPProductStorageLocationModel,
            data=storage_location,
            key_fields=["StorageLocation"],
            label="storage location data of product -> '{}' in plant -> '{}'".format(product_id, plant),
        )

    # end method definition

    def create_product_valuation(self, product_id: str, valuation: SAPProductValuationModel | dict) -> dict | None:
        """Create the valuation data of an SAP product (material) in a valuation area (plant).

        The valuation data is needed to post stock of the product (goods receipts and issues).

        Args:
            product_id (str):
                The product (material) number, e.g. "KT-4402".
            valuation (SAPProductValuationModel | dict):
                The valuation data (valuation area, valuation class, price control and price).

        Returns:
            dict | None:
                The created valuation data as returned by SAP or None in case of an error.

        """

        # The product is given by the URL - SAP needs it in the payload as well (also for models):
        if isinstance(valuation, dict):
            valuation = {**valuation, "Product": product_id}
        else:
            valuation = valuation.model_copy(update={"product_id": product_id})

        return self._create_odata_entity(
            service="API_PRODUCT_SRV",
            entity_set="A_Product('{}')/to_Valuation".format(self._quote_key(product_id)),
            model=SAPProductValuationModel,
            data=valuation,
            key_fields=["ValuationArea"],
            label="valuation data of product -> '{}'".format(product_id),
        )

    # end method definition

    def delete_product(self, product_id: str) -> bool:
        """Delete an SAP product (material) by setting its deletion flag (can be reset in SAP).

        SAP does not delete master data physically - the deletion flag (on client level)
        marks the product for archiving.

        Args:
            product_id (str):
                The product (material) number, e.g. "FG126".

        Returns:
            bool:
                True if the deletion flag has been set, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_PRODUCT_SRV",
            entity_path="A_Product('{}')".format(self._quote_key(product_id)),
            model=SAPProductModel,
            changes={"IsMarkedForDeletion": True},
            label="product -> '{}'".format(product_id),
        )

    # end method definition

    def undelete_product(self, product_id: str) -> bool:
        """Remove the deletion flag of an SAP product (material) - the reverse of delete_product().

        Args:
            product_id (str):
                The product (material) number, e.g. "FG126".

        Returns:
            bool:
                True if the deletion flag has been removed, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_PRODUCT_SRV",
            entity_path="A_Product('{}')".format(self._quote_key(product_id)),
            model=SAPProductModel,
            changes={"IsMarkedForDeletion": False},
            label="product -> '{}'".format(product_id),
        )

    # end method definition

    def create_material_bom(self, bom: SAPMaterialBOMModel | dict) -> dict | None:
        """Create a material BOM (bill of material) of a product in a plant with its items.

        With the usage "4" (plant maintenance) the BOM is the spare parts list of all
        equipment with this product as construction type.

        Args:
            bom (SAPMaterialBOMModel | dict):
                The data. A dictionary is validated against the SAPMaterialBOMModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created BOM as returned by SAP (including "BillOfMaterial") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_BILL_OF_MATERIAL_SRV",
            entity_set="MaterialBOM",
            model=SAPMaterialBOMModel,
            data=bom,
            key_fields=["BillOfMaterial"],
            label="material BOM",
        )

    # end method definition

    def iter_material_boms(
        self, query: SAPMaterialBOMQueryModel | None = None
    ) -> SAPODataIterator[SAPMaterialBOMResponseModel]:
        """Iterate over material BOMs - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPMaterialBOMQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all BOMs).

        Returns:
            SAPODataIterator[SAPMaterialBOMResponseModel]:
                The iterator over the BOMs.

        """

        return self._iter_odata_collection(
            service="API_BILL_OF_MATERIAL_SRV",
            entity_set="MaterialBOM",
            model=SAPMaterialBOMResponseModel,
            query=query or SAPMaterialBOMQueryModel(),
            label="material BOMs",
        )

    # end method definition

    def get_material_boms(
        self, query: SAPMaterialBOMQueryModel | None = None
    ) -> list[SAPMaterialBOMResponseModel] | None:
        """Get material BOMs as a list - e.g. the spare parts list (usage "4") of a product.

        All matching BOMs are read (page by page, see iter_material_boms()) and returned at once.

        Args:
            query (SAPMaterialBOMQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all BOMs).

        Returns:
            list[SAPMaterialBOMResponseModel] | None:
                The BOMs (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_material_boms(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP material BOMs.", len(results))

        return results

    # end method definition

    def update_material_bom(
        self,
        material: str,
        plant: str,
        usage: str = "1",
        alternative: str = "1",
        changes: dict | None = None,
        item_changes: dict[str, dict] | None = None,
    ) -> bool:
        """Update individual fields of a material BOM (header) and of its items.

        All changes are validated first and the items must belong to the BOM - otherwise nothing
        is changed. The items are changed first, the header last (see _update_odata_document()).
        BOMs with engineering change management (change numbers) are not supported.

        Args:
            material (str):
                The material (product) of the BOM, e.g. "P-100".
            plant (str):
                The plant of the BOM, e.g. "3000".
            usage (str, optional):
                The BOM usage, e.g. "1" (production) or "4" (plant maintenance / spare parts). Defaults to "1".
            alternative (str, optional):
                The alternative BOM. Defaults to "1".
            changes (dict | None, optional):
                The header fields to change - snake case attribute names of SAPMaterialBOMModel or OData
                property names, e.g. {"BOMHeaderText": "Pump assembly"}. Defaults to None (header unchanged).
            item_changes (dict[str, dict] | None, optional):
                The changes per item number or component, e.g. {"0010": {"BillOfMaterialItemQuantity": 2}}
                or {"100-100": {"BillOfMaterialItemQuantity": 2}} (snake case attribute names of
                SAPMaterialBOMItemModel or OData property names). Defaults to None (items unchanged).

        Returns:
            bool:
                True if the BOM (and its items) have been updated, False in case of an error.

        """

        label = "material BOM -> '{}' (plant -> '{}', usage -> '{}', alternative -> '{}')".format(
            material, plant, usage, alternative
        )
        if not changes and not item_changes:
            self.log_error("No changes given for SAP %s!", label)
            return False

        # The BOM has 7 key fields (e.g. the internal BOM number) - take its entity path from the BOM:
        response = self.do_request(
            url=self.service_url("API_BILL_OF_MATERIAL_SRV") + "/MaterialBOM",
            params={
                "$filter": "Material eq '{}' and Plant eq '{}' and BillOfMaterialVariantUsage eq '{}' and "
                "BillOfMaterialVariant eq '{}'".format(
                    self._quote_key(material),
                    self._quote_key(plant),
                    self._quote_key(usage),
                    self._quote_key(alternative),
                ),
                "$select": "BillOfMaterial",
            },
            show_error=False,
            show_warning=True,
            warning_message="Cannot get SAP {}".format(label),
        )
        boms = (response or {}).get("d", {}).get("results", [])
        if not boms:
            self.log_error("Cannot find SAP %s!", label)
            return False
        header_path = boms[0]["__metadata"]["uri"].rsplit("/", 1)[-1]

        return self._update_odata_document(
            service="API_BILL_OF_MATERIAL_SRV",
            label=label,
            header_path=header_path,
            header_model=SAPMaterialBOMModel,
            changes=changes,
            item_changes=item_changes,
            items=SAPODataItemSet(
                collection_path=header_path + "/to_BillOfMaterialItem",
                entity_set="MaterialBOMItem",
                key_properties=(),
                number_property="BillOfMaterialItemNumber",
                text_property="BillOfMaterialComponent",
                label="item",
            ),
            item_model=SAPMaterialBOMItemModel,
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

    def create_equipment(self, equipment: SAPEquipmentModel | dict) -> dict | None:
        """Create an SAP equipment (master data).

        Args:
            equipment (SAPEquipmentModel | dict):
                The data. A dictionary is validated against the SAPEquipmentModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created equipment as returned by SAP (including "Equipment") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_EQUIPMENT",
            entity_set="Equipment",
            model=SAPEquipmentModel,
            data=equipment,
            key_fields=["Equipment"],
            label="equipment",
        )

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

    def update_equipment(self, equipment_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP equipment.

        The changes are validated with the field definitions of SAPEquipmentModel. The equipment
        number, the category and the installation location (functional location, superordinate
        equipment) cannot be changed. Equipment data is time dependent: the currently valid time
        segment is changed.

        SAP ignores changes of an equipment with a deletion flag (without an error) - remove the
        flag with undelete_equipment() first.

        Args:
            equipment_id (str):
                The equipment number, e.g. "210100001".
            changes (dict):
                The fields to change - snake case attribute names of SAPEquipmentModel or OData
                property names, e.g. {"name": "Centrifugal pump P-100", "construction_year": "2019"}.

        Returns:
            bool:
                True if the equipment has been updated, False in case of an error.

        """

        equipment = self.get_equipment(equipment_id=equipment_id)
        if equipment is None:
            if not self.last_error:
                self.log_error("Cannot update SAP equipment -> '%s' - it does not exist!", equipment_id)
            return False
        if equipment.is_marked_for_deletion:
            self.log_error(
                "Cannot update SAP equipment -> '%s' - it is marked for deletion (remove the deletion flag first)!",
                equipment_id,
            )
            return False

        return self._update_odata_entity(
            service="API_EQUIPMENT",
            entity_path="Equipment(Equipment='{}',ValidityEndDate={})".format(
                self._quote_key(equipment_id), odata_literal(equipment.validity_end_date)
            ),
            model=SAPEquipmentModel,
            changes=changes,
            label="equipment -> '{}'".format(equipment_id),
        )

    # end method definition

    def delete_equipment(self, equipment_id: str) -> bool:
        """Delete an SAP equipment by setting its deletion flag (can be reset in SAP).

        SAP does not delete master data physically - the deletion flag marks it for archiving.
        Equipment data is time dependent: the flag is set for the currently valid time segment.

        Args:
            equipment_id (str):
                The equipment number, e.g. "210100001".

        Returns:
            bool:
                True if the deletion flag has been set, False in case of an error.

        """

        equipment = self.get_equipment(equipment_id=equipment_id)
        if equipment is None:
            if not self.last_error:
                self.log_error("Cannot delete SAP equipment -> '%s' - it does not exist!", equipment_id)
            return False

        # The function needs the time segment (part of the key) and the ETag of the equipment:
        result = self._call_odata_function(
            service="API_EQUIPMENT",
            function="SetEquipToMarkedForDeletion",
            parameters={"Equipment": equipment_id, "ValidityEndDate": equipment.validity_end_date},
            label="set the deletion flag of equipment -> '{}'".format(equipment_id),
            etag_entity_path="Equipment(Equipment='{}',ValidityEndDate={})".format(
                self._quote_key(equipment_id), odata_literal(equipment.validity_end_date)
            ),
        )

        return result is not None

    # end method definition

    def undelete_equipment(self, equipment_id: str) -> bool:
        """Remove the deletion flag of an SAP equipment - the reverse of delete_equipment().

        Args:
            equipment_id (str):
                The equipment number, e.g. "210100001".

        Returns:
            bool:
                True if the deletion flag has been removed, False in case of an error.

        """

        equipment = self.get_equipment(equipment_id=equipment_id)
        if equipment is None:
            if not self.last_error:
                self.log_error("Cannot undelete SAP equipment -> '%s' - it does not exist!", equipment_id)
            return False

        result = self._call_odata_function(
            service="API_EQUIPMENT",
            function="RsetEquipFromMarkedForDeletion",
            parameters={"Equipment": equipment_id, "ValidityEndDate": equipment.validity_end_date},
            label="remove the deletion flag of equipment -> '{}'".format(equipment_id),
            etag_entity_path="Equipment(Equipment='{}',ValidityEndDate={})".format(
                self._quote_key(equipment_id), odata_literal(equipment.validity_end_date)
            ),
        )

        return result is not None

    # end method definition

    def create_functional_location(self, functional_location: SAPFunctionalLocationModel | dict) -> dict | None:
        """Create an SAP functional location (master data).

        Args:
            functional_location (SAPFunctionalLocationModel | dict):
                The data. A dictionary is validated against the SAPFunctionalLocationModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created functional location as returned by SAP (including the internal ID
                "FunctionalLocation") or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_FUNCTIONALLOCATION",
            entity_set="FunctionalLocation",
            model=SAPFunctionalLocationModel,
            data=functional_location,
            key_fields=["FunctionalLocation"],
            label="functional location",
        )

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

    def update_functional_location(self, functional_location_id: str, changes: dict) -> bool:
        """Update individual fields of an SAP functional location.

        The changes are validated with the field definitions of SAPFunctionalLocationModel. The
        label (the key) cannot be changed. SAP rejects changes of a functional location with a
        deletion flag - remove the flag with undelete_functional_location() first.

        Args:
            functional_location_id (str):
                The internal functional location ID, e.g. "1010-SP-PMP".
            changes (dict):
                The fields to change - snake case attribute names of SAPFunctionalLocationModel or
                OData property names, e.g. {"name": "Pump station 1", "main_work_center": "RES-0100"}.

        Returns:
            bool:
                True if the functional location has been updated, False in case of an error.

        """

        return self._update_odata_entity(
            service="API_FUNCTIONALLOCATION",
            entity_path="FunctionalLocation('{}')".format(self._quote_key(functional_location_id)),
            model=SAPFunctionalLocationModel,
            changes=changes,
            label="functional location -> '{}'".format(functional_location_id),
        )

    # end method definition

    def delete_functional_location(self, functional_location_id: str) -> bool:
        """Delete an SAP functional location by setting its deletion flag (can be reset in SAP).

        SAP does not delete master data physically - the deletion flag marks it for archiving.

        Args:
            functional_location_id (str):
                The internal functional location ID, e.g. "1010-SP-PMP".

        Returns:
            bool:
                True if the deletion flag has been set, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_FUNCTIONALLOCATION",
            function="SetFuncLocToMarkedForDeletion",
            parameters={"FunctionalLocation": functional_location_id},
            label="set the deletion flag of functional location -> '{}'".format(functional_location_id),
            # The function needs the ETag of the functional location (428 Precondition required otherwise):
            etag_entity_path="FunctionalLocation('{}')".format(self._quote_key(functional_location_id)),
        )

        return result is not None

    # end method definition

    def undelete_functional_location(self, functional_location_id: str) -> bool:
        """Remove the deletion flag of an SAP functional location - the reverse of delete_functional_location().

        Args:
            functional_location_id (str):
                The internal functional location ID, e.g. "1010-SP-PMP".

        Returns:
            bool:
                True if the deletion flag has been removed, False in case of an error.

        """

        result = self._call_odata_function(
            service="API_FUNCTIONALLOCATION",
            function="RsetFuncLocFromMrkdForDeletion",
            parameters={"FunctionalLocation": functional_location_id},
            label="remove the deletion flag of functional location -> '{}'".format(functional_location_id),
            etag_entity_path="FunctionalLocation('{}')".format(self._quote_key(functional_location_id)),
        )

        return result is not None

    # end method definition

    def create_business_partner(self, business_partner: SAPBusinessPartnerModel | dict) -> dict | None:
        """Create an SAP business partner (organization) with its addresses, roles and supplier / customer data.

        With a supplier or customer role (e.g. FLVN00 / FLCU00) SAP also creates the
        supplier / customer - depending on the customizing of the grouping. The purchasing
        organization data (role FLVN01) and company code data of the supplier and the sales
        area data (role FLCU01) and company code data of the customer can be created in the
        same request. Business partners cannot be deleted with the API.

        Args:
            business_partner (SAPBusinessPartnerModel | dict):
                The data. A dictionary is validated against the SAPBusinessPartnerModel and can use
                either the snake case attribute names or the OData property names.

        Returns:
            dict | None:
                The created business partner as returned by SAP (including "BusinessPartner")
                or None in case of an error.

        """

        return self._create_odata_entity(
            service="API_BUSINESS_PARTNER",
            entity_set="A_BusinessPartner",
            model=SAPBusinessPartnerModel,
            data=business_partner,
            key_fields=["BusinessPartner"],
            label="business partner",
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
                Whether to read the roles, addresses, supplier data (purchasing organizations,
                company codes) and customer data (sales areas, company codes) as well.
                Defaults to True.

        Returns:
            SAPBusinessPartnerResponseModel | None:
                The business partner or None if it does not exist or in case of an error.

        """

        return self._get_odata_entity(
            service="API_BUSINESS_PARTNER",
            entity_path="A_BusinessPartner('{}')".format(self._quote_key(business_partner_id)),
            model=SAPBusinessPartnerResponseModel,
            params={"$expand": BUSINESS_PARTNER_DETAILS_EXPAND} if expand_items else None,
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
                Whether to read the roles, addresses, supplier data (purchasing organizations,
                company codes) and customer data (sales areas, company codes) as well - see
                get_business_partner(). Defaults to True.

        Returns:
            SAPBusinessPartnerResponseModel | None:
                The business partner or None if it does not exist or in case of an error.

        """

        # Two entries to detect ambiguous assignments (there should be exactly one business partner):
        entries = self.get_customers(query=SAPCustomerQueryModel(customer_ids=[customer_id], limit=2))
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
            self.logger.warning("Cannot find SAP customer -> '%s'", customer_id, report=True)
            return None
        if not expand_items:
            return entries[0]

        # The collection only expands the roles - the business partner itself has all details (e.g. addresses):
        return self.get_business_partner(business_partner_id=entries[0].business_partner_id, expand_items=True)

    # end method definition

    def iter_suppliers(
        self, query: SAPSupplierQueryModel | None = None
    ) -> SAPODataIterator[SAPBusinessPartnerResponseModel]:
        """Iterate over SAP suppliers - reading them page by page from SAP.

        Use this for large result sets: only one page is held in memory at a time.
        Errors are logged and end the iteration (check the 'failed' attribute of the
        returned iterator afterwards).

        Args:
            query (SAPSupplierQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all suppliers).

        Returns:
            SAPODataIterator[SAPBusinessPartnerResponseModel]:
                The iterator over the suppliers.

        """

        return self._iter_odata_collection(
            service="API_BUSINESS_PARTNER",
            entity_set="A_BusinessPartner",
            model=SAPBusinessPartnerResponseModel,
            query=query or SAPSupplierQueryModel(),
            label="suppliers",
        )

    # end method definition

    def get_suppliers(self, query: SAPSupplierQueryModel | None = None) -> list[SAPBusinessPartnerResponseModel] | None:
        """Get SAP suppliers as a list.

        All matching suppliers are read (page by page, see iter_suppliers()) and returned at once.
        For very large result sets prefer iter_suppliers().

        Args:
            query (SAPSupplierQueryModel | None, optional):
                The search criteria (filters, sort order, limit, page size). Defaults to None (all suppliers).

        Returns:
            list[SAPBusinessPartnerResponseModel] | None:
                The suppliers (an empty list if none match) or None in case of an error.

        """

        entries = self.iter_suppliers(query=query)
        results = list(entries)
        if entries.failed:
            return None

        self.logger.info("Got %d SAP suppliers.", len(results))

        return results

    # end method definition

    def get_supplier(self, supplier_id: str, expand_items: bool = True) -> SAPBusinessPartnerResponseModel | None:
        """Get the business partner of a supplier number (master data).

        In S/4HANA suppliers are business partners with the supplier role (customer / vendor
        integration). The supplier (vendor) number (as used in business documents and as business object
        ID of LFA1 business workspaces) is not necessarily the business partner number, so
        the business partner is looked up by its "Supplier" property.

        Args:
            supplier_id (str):
                The supplier number, e.g. "17300001".
            expand_items (bool, optional):
                Whether to read the roles, addresses, supplier data (purchasing organizations,
                company codes) and customer data (sales areas, company codes) as well - see
                get_business_partner(). Defaults to True.

        Returns:
            SAPBusinessPartnerResponseModel | None:
                The business partner or None if it does not exist or in case of an error.

        """

        # Two entries to detect ambiguous assignments (there should be exactly one business partner):
        entries = self.get_suppliers(query=SAPSupplierQueryModel(supplier_ids=[supplier_id], limit=2))
        if entries is None:
            return None
        if len(entries) > 1:
            self.log_error(
                "SAP supplier -> '%s' is assigned to several business partners -> %s",
                supplier_id,
                ", ".join(entry.business_partner_id for entry in entries),
            )
            return None
        if not entries:
            self.logger.warning("Cannot find SAP supplier -> '%s'", supplier_id, report=True)
            return None
        if not expand_items:
            return entries[0]

        # The collection only expands the roles - the business partner itself has all details (e.g. addresses):
        return self.get_business_partner(business_partner_id=entries[0].business_partner_id, expand_items=True)

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

        query, failed = self._resolve_text_search(
            service="API_SALESORGANIZATION_SRV",
            query=query or SAPSalesOrganizationQueryModel(),
            label="sales organizations",
        )
        if failed:
            return SAPODataIterator(_failed_odata_read())
        if query is None:
            return SAPODataIterator(iter([]))

        return self._iter_odata_collection(
            service="API_SALESORGANIZATION_SRV",
            entity_set="A_SalesOrganization",
            model=SAPSalesOrganizationResponseModel,
            query=query,
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

        query, failed = self._resolve_text_search(
            service="API_COSTCENTER_SRV", query=query or SAPCostCenterQueryModel(), label="cost centers"
        )
        if failed:
            return SAPODataIterator(_failed_odata_read())
        if query is None:
            return SAPODataIterator(iter([]))

        return self._iter_odata_collection(
            service="API_COSTCENTER_SRV",
            entity_set="A_CostCenter",
            model=SAPCostCenterResponseModel,
            query=query,
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

        query, failed = self._resolve_text_search(
            service="API_PROFITCENTER_SRV", query=query or SAPProfitCenterQueryModel(), label="profit centers"
        )
        if failed:
            return SAPODataIterator(_failed_odata_read())
        if query is None:
            return SAPODataIterator(iter([]))

        return self._iter_odata_collection(
            service="API_PROFITCENTER_SRV",
            entity_set="A_ProfitCenter",
            model=SAPProfitCenterResponseModel,
            query=query,
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

        query, failed = self._resolve_text_search(
            service="API_GLACCOUNTINCHARTOFACCOUNTS_SRV", query=query or SAPGLAccountQueryModel(), label="G/L accounts"
        )
        if failed:
            return SAPODataIterator(_failed_odata_read())
        if query is None:
            return SAPODataIterator(iter([]))

        return self._iter_odata_collection(
            service="API_GLACCOUNTINCHARTOFACCOUNTS_SRV",
            entity_set="A_GLAccountInChartOfAccounts",
            model=SAPGLAccountResponseModel,
            query=query,
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

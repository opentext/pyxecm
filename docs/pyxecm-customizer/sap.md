---
hide:
  - navigation
---

# SAP

The `SAP` class reads and changes SAP S/4HANA business objects through SAP's released OData APIs,
and calls RFC function modules and BAPIs. OData needs no extra packages. Optional features need
these extras:

```bash
pip install "pyxecm[sap]"    # RFC calls via PyRFC (also needs the SAP NW RFC SDK)
pip install "pyxecm[saml]"   # principal propagation - see SAP Authentication / SSO
pip install "pyxecm[forms]"  # PDF renderings of SAP documents (ReportLab)
```

Related pages:

- [SAP APIs that must be activated](sap-apis.md) - the OData services per business domain and how
  to activate and authorize them.
- [SAP Authentication / SSO](sap-authentication.md) - calling SAP as the individual user
  (principal propagation) instead of a technical user.
- [SAP Models](sap-models.md) - reference of the Pydantic models in `pyxecm_customizer.sap_models`.

## Quick start

### Connect

SAP can be called with one technical user for everybody, or as the individual user (principal
propagation - SAP then applies the user's own authorizations and records the user as author of
changes):

#### Technical user

```python
from pyxecm_customizer.sap import SAP

sap = SAP(
    username="...",  # technical (service) user with the authorizations of all calls
    password="...",
    system_id="S4H",
    client="100",
    base_url="https://s4.example.com:44300",
)
```

#### Principal propagation

pyxecm signs a SAML 2.0 assertion for the user and exchanges it for an SAP access token
(needs the `saml` extra and the SAP setup in [SAP Authentication / SSO](sap-authentication.md)):

```python
from pathlib import Path

from pyxecm_customizer.sap import SAML_NAMEID_FORMAT_EMAIL, SAP, BearerAuth, get_oauth_scope

# Once per process - pyxecm's identity provider with its key pair (trusted in SAP transaction SAML2):
identity_provider = SAP(
    username="",  # no technical user needed
    password="",
    system_id="S4H",
    client="100",
    base_url="https://s4.example.com:44300",
    saml_idp_private_key=Path("/run/secrets/saml-idp.key").read_text(),
    saml_idp_certificate=Path("/run/secrets/saml-idp.crt").read_text(),
    saml_issuer="pyxecm-idp",  # entity ID of the trusted provider in SAML2
    saml_audience="S4HCLNT100",  # local provider name of the SAP client in SAML2
)

# Per user - an access token for the user of a verified session (never from request input):
token = identity_provider.get_oauth_access_token_for_user(
    user_id="jane.smith@example.com",
    nameid_format=SAML_NAMEID_FORMAT_EMAIL,  # as mapped in SAML2 (identity federation)
    client_id="PYXECM_OAUTH",  # OAuth 2.0 client in SAP transaction SOAUTH2
    client_secret="...",  # from a secret store
    scope=get_oauth_scope(),  # all services - SAP grants those the client and user may use
)
if token is None:
    raise RuntimeError(identity_provider.last_error)

# One SAP object per user - all OData calls run as this user:
sap = SAP(
    username="",
    password="",
    system_id="S4H",
    client="100",
    base_url="https://s4.example.com:44300",
    auth=BearerAuth(token["access_token"], scope=token.get("scope")),
)
```

The token expires after `token["expires_in"]` seconds and is not renewed - keep the user's
SAP object for a shorter time and then get a new token. `sap.granted_scopes` tells which
OData services the user can call. See [Usage](sap-authentication.md#usage) for details.

### Read and update

```python
from pyxecm_customizer.sap_models import SAPSalesOrderQueryModel

orders = sap.get_sales_orders(SAPSalesOrderQueryModel(sold_to_party="52001", limit=10))
if orders is None:
    print("Reading the sales orders failed:", sap.last_error)
else:
    for order in orders:
        print(order.order_id, order.order_date, order.total_net_amount, order.currency)

sap.update_sales_order(order_id="413", item_changes={"10": {"quantity": 5}})
```

## Concepts

### Models

Every business object has a family of Pydantic models in `pyxecm_customizer.sap_models`, named
after the object (e.g. `SAPSalesOrder…`):

| Model                      | Used for                                                                                   |
| -------------------------- | ------------------------------------------------------------------------------------------ |
| `SAP<Object>QueryModel`    | The search criteria of `get_<objects>()` / `iter_<objects>()`, incl. `limit` and `sort_by` |
| `SAP<Object>Model`         | The data of `create_<object>()`, validated before anything is sent to SAP                  |
| `SAP<Object>ResponseModel` | The result of the read methods                                                             |
| `SAP<Object>Item…Model`    | Items and other sub-entities (schedule lines, operations, ...)                             |

The attributes are snake case (`sold_to_party`); their aliases are the OData property names
(`SoldToParty`). Both are accepted as input, and `str()` of a model is compact JSON with the
OData names. Response models contain the business-relevant properties only - SAP's technical
properties are dropped. `create_…()` methods also accept a plain dict.

### Return values and errors

The methods don't raise exceptions for SAP or connection errors. Read methods return `None`,
change methods `False` (or `None` for create methods, which return the created object as SAP
sends it, including its number). The reason is in `sap.last_error` - per thread, so it is safe in
multithreaded code - or can be collected with `pyxecm.capture_errors()`.

### Finding and reading

- `get_<objects>(query)` returns a list; without `limit` it reads all matching objects.
- `iter_<objects>(query)` reads page by page and holds only one page in memory - use it for large
  result sets. After the loop, its `failed` attribute tells whether all objects were read.
- `get_<object>(id)` reads one object, by default with its items.

Composite keys are separate parameters, e.g. `get_goods_movement(document_year, document)`.

### Updating

`update_<object>(id, changes, item_changes)` changes individual fields: `changes` for the header,
`item_changes` per item number (e.g. `{"10": {"quantity": 5}}`). Field names can be
attribute names or OData names. All changes are checked against the service's `$metadata` first
(unknown, read-only or wrongly typed fields) - if one is invalid, nothing is changed. Items are
updated first, the header last.

Status changes (release, complete, close, ...) are separate methods that take an action enum, e.g.
`change_maintenance_order_status(order_id, SAPMaintenanceOrderAction.RELEASE)`. The enums are in
`sap_models` (`SAPMaintenanceOrderAction`, `SAPOutboundDeliveryAction`, ...).

### What the class takes care of

- OData V2 and V4: the differences (URLs, JSON formats, paging, actions) are hidden behind the
  same methods and models.
- CSRF tokens for changing requests, SAP session cookies and one HTTP session per thread.
- The SAP client (`sap-client`) and logon language (`sap-language`) of every request.
- Expired SAP sessions are renewed once; a rejected access token is reported in `last_error`.

## Business objects

One table per business domain - the same grouping as in [SAP APIs that must be
activated](sap-apis.md#odata-services), where the OData service of each object is listed. The
second line of the *Object* column is the prefix of the object's models (see [Models](#models)).
"-" means the API (or pyxecm) offers no such operation. The method names link to their reference
below.

### Plant Maintenance

Operations and components are read with their maintenance order. Equipment and functional locations are under [Logistics Master Data](#logistics-master-data).

| Object | Create | Read | Update | Delete | Actions |
| --- | --- | --- | --- | --- | --- |
| Maintenance notification <br><code>SAPMaintenance<wbr>Notification…</code> | [<code>create_<wbr>maintenance_<wbr>notification</code>](#pyxecm_customizer.sap.SAP.create_maintenance_notification)<br>[<code>create_<wbr>maintenance_<wbr>notification_<wbr>item</code>](#pyxecm_customizer.sap.SAP.create_maintenance_notification_item) | [<code>get_<wbr>maintenance_<wbr>notifications</code>](#pyxecm_customizer.sap.SAP.get_maintenance_notifications)<br>[<code>iter_<wbr>maintenance_<wbr>notifications</code>](#pyxecm_customizer.sap.SAP.iter_maintenance_notifications)<br>[<code>get_<wbr>maintenance_<wbr>notification</code>](#pyxecm_customizer.sap.SAP.get_maintenance_notification) | [<code>update_<wbr>maintenance_<wbr>notification</code>](#pyxecm_customizer.sap.SAP.update_maintenance_notification) | - | [<code>change_<wbr>maintenance_<wbr>notification_<wbr>status</code>](#pyxecm_customizer.sap.SAP.change_maintenance_notification_status) |
| Maintenance order <br><code>SAPMaintenance<wbr>Order…</code> | [<code>create_<wbr>maintenance_<wbr>order</code>](#pyxecm_customizer.sap.SAP.create_maintenance_order) | [<code>get_<wbr>maintenance_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.get_maintenance_orders)<br>[<code>iter_<wbr>maintenance_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.iter_maintenance_orders)<br>[<code>get_<wbr>maintenance_<wbr>order</code>](#pyxecm_customizer.sap.SAP.get_maintenance_order) | [<code>update_<wbr>maintenance_<wbr>order</code>](#pyxecm_customizer.sap.SAP.update_maintenance_order) | [<code>delete_<wbr>maintenance_<wbr>order</code>](#pyxecm_customizer.sap.SAP.delete_maintenance_order) | [<code>change_<wbr>maintenance_<wbr>order_<wbr>status</code>](#pyxecm_customizer.sap.SAP.change_maintenance_order_status)<br>[<code>get_<wbr>maintenance_<wbr>order_<wbr>deletion_<wbr>steps</code>](#pyxecm_customizer.sap.SAP.get_maintenance_order_deletion_steps)<br>[<code>expand_<wbr>maintenance_<wbr>order_<wbr>task_<wbr>list</code>](#pyxecm_customizer.sap.SAP.expand_maintenance_order_task_list) |
| Maintenance order operation <br><code>SAPMaintenance<wbr>Order<wbr>Operation…</code> | [<code>create_<wbr>maintenance_<wbr>order_<wbr>operation</code>](#pyxecm_customizer.sap.SAP.create_maintenance_order_operation) | - | [<code>update_<wbr>maintenance_<wbr>order_<wbr>operation</code>](#pyxecm_customizer.sap.SAP.update_maintenance_order_operation) | [<code>delete_<wbr>maintenance_<wbr>order_<wbr>operation</code>](#pyxecm_customizer.sap.SAP.delete_maintenance_order_operation) | [<code>change_<wbr>maintenance_<wbr>order_<wbr>operation_<wbr>status</code>](#pyxecm_customizer.sap.SAP.change_maintenance_order_operation_status) |
| Maintenance order component <br><code>SAPMaintenance<wbr>Order<wbr>Component…</code> | [<code>create_<wbr>maintenance_<wbr>order_<wbr>component</code>](#pyxecm_customizer.sap.SAP.create_maintenance_order_component) | - | - | - | - |
| Maintenance order confirmation <br><code>SAPMaintenance<wbr>Order<wbr>Confirmation…</code> | [<code>create_<wbr>maintenance_<wbr>order_<wbr>confirmation</code>](#pyxecm_customizer.sap.SAP.create_maintenance_order_confirmation) | [<code>get_<wbr>maintenance_<wbr>order_<wbr>confirmations</code>](#pyxecm_customizer.sap.SAP.get_maintenance_order_confirmations)<br>[<code>iter_<wbr>maintenance_<wbr>order_<wbr>confirmations</code>](#pyxecm_customizer.sap.SAP.iter_maintenance_order_confirmations)<br>[<code>get_<wbr>maintenance_<wbr>order_<wbr>confirmation</code>](#pyxecm_customizer.sap.SAP.get_maintenance_order_confirmation) | - | - | [<code>cancel_<wbr>maintenance_<wbr>order_<wbr>confirmation</code>](#pyxecm_customizer.sap.SAP.cancel_maintenance_order_confirmation) |
| Maintenance plan <br><code>SAPMaintenance<wbr>Plan…</code> | [<code>create_<wbr>maintenance_<wbr>plan</code>](#pyxecm_customizer.sap.SAP.create_maintenance_plan) | [<code>get_<wbr>maintenance_<wbr>plans</code>](#pyxecm_customizer.sap.SAP.get_maintenance_plans)<br>[<code>iter_<wbr>maintenance_<wbr>plans</code>](#pyxecm_customizer.sap.SAP.iter_maintenance_plans)<br>[<code>iter_<wbr>maintenance_<wbr>plan_<wbr>items</code>](#pyxecm_customizer.sap.SAP.iter_maintenance_plan_items)<br>[<code>get_<wbr>maintenance_<wbr>plan</code>](#pyxecm_customizer.sap.SAP.get_maintenance_plan) | [<code>update_<wbr>maintenance_<wbr>plan</code>](#pyxecm_customizer.sap.SAP.update_maintenance_plan) | - | [<code>change_<wbr>maintenance_<wbr>plan_<wbr>status</code>](#pyxecm_customizer.sap.SAP.change_maintenance_plan_status) |
| Maintenance task list <br><code>SAPTask<wbr>List…</code> | [<code>create_<wbr>task_<wbr>list</code>](#pyxecm_customizer.sap.SAP.create_task_list) | [<code>get_<wbr>task_<wbr>lists</code>](#pyxecm_customizer.sap.SAP.get_task_lists)<br>[<code>iter_<wbr>task_<wbr>lists</code>](#pyxecm_customizer.sap.SAP.iter_task_lists)<br>[<code>get_<wbr>task_<wbr>list</code>](#pyxecm_customizer.sap.SAP.get_task_list) | [<code>update_<wbr>task_<wbr>list</code>](#pyxecm_customizer.sap.SAP.update_task_list) | - | - |

### Sales

| Object | Create | Read | Update | Delete | Actions |
| --- | --- | --- | --- | --- | --- |
| Sales order <br><code>SAPSales<wbr>Order…</code> | [<code>create_<wbr>sales_<wbr>order</code>](#pyxecm_customizer.sap.SAP.create_sales_order)<br>[<code>create_<wbr>sales_<wbr>order_<wbr>item</code>](#pyxecm_customizer.sap.SAP.create_sales_order_item) | [<code>get_<wbr>sales_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.get_sales_orders)<br>[<code>iter_<wbr>sales_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.iter_sales_orders)<br>[<code>get_<wbr>sales_<wbr>order</code>](#pyxecm_customizer.sap.SAP.get_sales_order) | [<code>update_<wbr>sales_<wbr>order</code>](#pyxecm_customizer.sap.SAP.update_sales_order) | [<code>delete_<wbr>sales_<wbr>order</code>](#pyxecm_customizer.sap.SAP.delete_sales_order)<br>[<code>delete_<wbr>sales_<wbr>order_<wbr>item</code>](#pyxecm_customizer.sap.SAP.delete_sales_order_item) | - |
| Sales contract <br><code>SAPSales<wbr>Contract…</code> | [<code>create_<wbr>sales_<wbr>contract</code>](#pyxecm_customizer.sap.SAP.create_sales_contract) | [<code>get_<wbr>sales_<wbr>contracts</code>](#pyxecm_customizer.sap.SAP.get_sales_contracts)<br>[<code>iter_<wbr>sales_<wbr>contracts</code>](#pyxecm_customizer.sap.SAP.iter_sales_contracts)<br>[<code>get_<wbr>sales_<wbr>contract</code>](#pyxecm_customizer.sap.SAP.get_sales_contract) | [<code>update_<wbr>sales_<wbr>contract</code>](#pyxecm_customizer.sap.SAP.update_sales_contract) | [<code>delete_<wbr>sales_<wbr>contract</code>](#pyxecm_customizer.sap.SAP.delete_sales_contract) | - |
| Credit memo request <br><code>SAPCredit<wbr>Memo<wbr>Request…</code> | [<code>create_<wbr>credit_<wbr>memo_<wbr>request</code>](#pyxecm_customizer.sap.SAP.create_credit_memo_request) | [<code>get_<wbr>credit_<wbr>memo_<wbr>requests</code>](#pyxecm_customizer.sap.SAP.get_credit_memo_requests)<br>[<code>iter_<wbr>credit_<wbr>memo_<wbr>requests</code>](#pyxecm_customizer.sap.SAP.iter_credit_memo_requests)<br>[<code>get_<wbr>credit_<wbr>memo_<wbr>request</code>](#pyxecm_customizer.sap.SAP.get_credit_memo_request) | [<code>update_<wbr>credit_<wbr>memo_<wbr>request</code>](#pyxecm_customizer.sap.SAP.update_credit_memo_request) | [<code>delete_<wbr>credit_<wbr>memo_<wbr>request</code>](#pyxecm_customizer.sap.SAP.delete_credit_memo_request) | [<code>change_<wbr>credit_<wbr>memo_<wbr>request_<wbr>status</code>](#pyxecm_customizer.sap.SAP.change_credit_memo_request_status) |
| Debit memo request <br><code>SAPDebit<wbr>Memo<wbr>Request…</code> | [<code>create_<wbr>debit_<wbr>memo_<wbr>request</code>](#pyxecm_customizer.sap.SAP.create_debit_memo_request) | [<code>get_<wbr>debit_<wbr>memo_<wbr>requests</code>](#pyxecm_customizer.sap.SAP.get_debit_memo_requests)<br>[<code>iter_<wbr>debit_<wbr>memo_<wbr>requests</code>](#pyxecm_customizer.sap.SAP.iter_debit_memo_requests)<br>[<code>get_<wbr>debit_<wbr>memo_<wbr>request</code>](#pyxecm_customizer.sap.SAP.get_debit_memo_request) | [<code>update_<wbr>debit_<wbr>memo_<wbr>request</code>](#pyxecm_customizer.sap.SAP.update_debit_memo_request) | [<code>delete_<wbr>debit_<wbr>memo_<wbr>request</code>](#pyxecm_customizer.sap.SAP.delete_debit_memo_request) | - |
| Outbound delivery <br><code>SAPOutbound<wbr>Delivery…</code> | [<code>create_<wbr>outbound_<wbr>delivery</code>](#pyxecm_customizer.sap.SAP.create_outbound_delivery) | [<code>get_<wbr>outbound_<wbr>deliveries</code>](#pyxecm_customizer.sap.SAP.get_outbound_deliveries)<br>[<code>iter_<wbr>outbound_<wbr>deliveries</code>](#pyxecm_customizer.sap.SAP.iter_outbound_deliveries)<br>[<code>iter_<wbr>outbound_<wbr>delivery_<wbr>items</code>](#pyxecm_customizer.sap.SAP.iter_outbound_delivery_items)<br>[<code>get_<wbr>outbound_<wbr>delivery</code>](#pyxecm_customizer.sap.SAP.get_outbound_delivery) | [<code>update_<wbr>outbound_<wbr>delivery</code>](#pyxecm_customizer.sap.SAP.update_outbound_delivery) | [<code>delete_<wbr>outbound_<wbr>delivery</code>](#pyxecm_customizer.sap.SAP.delete_outbound_delivery) | [<code>change_<wbr>outbound_<wbr>delivery_<wbr>status</code>](#pyxecm_customizer.sap.SAP.change_outbound_delivery_status) |

### Billing

| Object | Create | Read | Update | Delete | Actions |
| --- | --- | --- | --- | --- | --- |
| Billing document <br><code>SAPBilling<wbr>Document…</code> | - | [<code>get_<wbr>billing_<wbr>documents</code>](#pyxecm_customizer.sap.SAP.get_billing_documents)<br>[<code>iter_<wbr>billing_<wbr>documents</code>](#pyxecm_customizer.sap.SAP.iter_billing_documents)<br>[<code>iter_<wbr>billing_<wbr>document_<wbr>items</code>](#pyxecm_customizer.sap.SAP.iter_billing_document_items)<br>[<code>get_<wbr>billing_<wbr>document</code>](#pyxecm_customizer.sap.SAP.get_billing_document) | - | - | [<code>cancel_<wbr>billing_<wbr>document</code>](#pyxecm_customizer.sap.SAP.cancel_billing_document)<br>[<code>get_<wbr>billing_<wbr>document_<wbr>pdf</code>](#pyxecm_customizer.sap.SAP.get_billing_document_pdf) |
| Billing document request <br><code>SAPBilling<wbr>Document<wbr>Request…</code> | - | [<code>get_<wbr>billing_<wbr>document_<wbr>requests</code>](#pyxecm_customizer.sap.SAP.get_billing_document_requests)<br>[<code>iter_<wbr>billing_<wbr>document_<wbr>requests</code>](#pyxecm_customizer.sap.SAP.iter_billing_document_requests)<br>[<code>get_<wbr>billing_<wbr>document_<wbr>request</code>](#pyxecm_customizer.sap.SAP.get_billing_document_request) | - | [<code>delete_<wbr>billing_<wbr>document_<wbr>request</code>](#pyxecm_customizer.sap.SAP.delete_billing_document_request) | [<code>reject_<wbr>billing_<wbr>document_<wbr>request</code>](#pyxecm_customizer.sap.SAP.reject_billing_document_request) |

### Purchasing

| Object | Create | Read | Update | Delete | Actions |
| --- | --- | --- | --- | --- | --- |
| Purchase requisition <br><code>SAPPurchase<wbr>Requisition…</code> | [<code>create_<wbr>purchase_<wbr>requisition</code>](#pyxecm_customizer.sap.SAP.create_purchase_requisition)<br>[<code>create_<wbr>purchase_<wbr>requisition_<wbr>item</code>](#pyxecm_customizer.sap.SAP.create_purchase_requisition_item) | [<code>get_<wbr>purchase_<wbr>requisitions</code>](#pyxecm_customizer.sap.SAP.get_purchase_requisitions)<br>[<code>iter_<wbr>purchase_<wbr>requisitions</code>](#pyxecm_customizer.sap.SAP.iter_purchase_requisitions)<br>[<code>get_<wbr>purchase_<wbr>requisition</code>](#pyxecm_customizer.sap.SAP.get_purchase_requisition) | [<code>update_<wbr>purchase_<wbr>requisition</code>](#pyxecm_customizer.sap.SAP.update_purchase_requisition) | [<code>delete_<wbr>purchase_<wbr>requisition</code>](#pyxecm_customizer.sap.SAP.delete_purchase_requisition)<br>[<code>delete_<wbr>purchase_<wbr>requisition_<wbr>item</code>](#pyxecm_customizer.sap.SAP.delete_purchase_requisition_item) | - |
| Purchase order <br><code>SAPPurchase<wbr>Order…</code> | [<code>create_<wbr>purchase_<wbr>order</code>](#pyxecm_customizer.sap.SAP.create_purchase_order) | [<code>get_<wbr>purchase_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.get_purchase_orders)<br>[<code>iter_<wbr>purchase_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.iter_purchase_orders)<br>[<code>get_<wbr>purchase_<wbr>order</code>](#pyxecm_customizer.sap.SAP.get_purchase_order) | [<code>update_<wbr>purchase_<wbr>order</code>](#pyxecm_customizer.sap.SAP.update_purchase_order) | [<code>delete_<wbr>purchase_<wbr>order</code>](#pyxecm_customizer.sap.SAP.delete_purchase_order) | - |
| Purchase contract <br><code>SAPPurchase<wbr>Contract…</code> | [<code>create_<wbr>purchase_<wbr>contract</code>](#pyxecm_customizer.sap.SAP.create_purchase_contract)<br>[<code>create_<wbr>purchase_<wbr>contract_<wbr>item</code>](#pyxecm_customizer.sap.SAP.create_purchase_contract_item) | [<code>get_<wbr>purchase_<wbr>contracts</code>](#pyxecm_customizer.sap.SAP.get_purchase_contracts)<br>[<code>iter_<wbr>purchase_<wbr>contracts</code>](#pyxecm_customizer.sap.SAP.iter_purchase_contracts)<br>[<code>get_<wbr>purchase_<wbr>contract</code>](#pyxecm_customizer.sap.SAP.get_purchase_contract) | [<code>update_<wbr>purchase_<wbr>contract</code>](#pyxecm_customizer.sap.SAP.update_purchase_contract)<br>[<code>update_<wbr>purchase_<wbr>contract_<wbr>item</code>](#pyxecm_customizer.sap.SAP.update_purchase_contract_item) | [<code>delete_<wbr>purchase_<wbr>contract</code>](#pyxecm_customizer.sap.SAP.delete_purchase_contract) | - |
| Inbound delivery <br><code>SAPInbound<wbr>Delivery…</code> | [<code>create_<wbr>inbound_<wbr>delivery</code>](#pyxecm_customizer.sap.SAP.create_inbound_delivery) | [<code>get_<wbr>inbound_<wbr>deliveries</code>](#pyxecm_customizer.sap.SAP.get_inbound_deliveries)<br>[<code>iter_<wbr>inbound_<wbr>deliveries</code>](#pyxecm_customizer.sap.SAP.iter_inbound_deliveries)<br>[<code>iter_<wbr>inbound_<wbr>delivery_<wbr>items</code>](#pyxecm_customizer.sap.SAP.iter_inbound_delivery_items)<br>[<code>get_<wbr>inbound_<wbr>delivery</code>](#pyxecm_customizer.sap.SAP.get_inbound_delivery) | [<code>update_<wbr>inbound_<wbr>delivery</code>](#pyxecm_customizer.sap.SAP.update_inbound_delivery) | [<code>delete_<wbr>inbound_<wbr>delivery</code>](#pyxecm_customizer.sap.SAP.delete_inbound_delivery) | [<code>change_<wbr>inbound_<wbr>delivery_<wbr>status</code>](#pyxecm_customizer.sap.SAP.change_inbound_delivery_status) |
| Supplier invoice <br><code>SAPSupplier<wbr>Invoice…</code> | [<code>create_<wbr>supplier_<wbr>invoice</code>](#pyxecm_customizer.sap.SAP.create_supplier_invoice) | [<code>get_<wbr>supplier_<wbr>invoices</code>](#pyxecm_customizer.sap.SAP.get_supplier_invoices)<br>[<code>iter_<wbr>supplier_<wbr>invoices</code>](#pyxecm_customizer.sap.SAP.iter_supplier_invoices)<br>[<code>get_<wbr>supplier_<wbr>invoice_<wbr>items</code>](#pyxecm_customizer.sap.SAP.get_supplier_invoice_items)<br>[<code>get_<wbr>supplier_<wbr>invoice_<wbr>gl_<wbr>account_<wbr>items</code>](#pyxecm_customizer.sap.SAP.get_supplier_invoice_gl_account_items)<br>[<code>get_<wbr>supplier_<wbr>invoice</code>](#pyxecm_customizer.sap.SAP.get_supplier_invoice) | - | [<code>delete_<wbr>supplier_<wbr>invoice</code>](#pyxecm_customizer.sap.SAP.delete_supplier_invoice) | [<code>post_<wbr>supplier_<wbr>invoice</code>](#pyxecm_customizer.sap.SAP.post_supplier_invoice)<br>[<code>release_<wbr>supplier_<wbr>invoice</code>](#pyxecm_customizer.sap.SAP.release_supplier_invoice)<br>[<code>cancel_<wbr>supplier_<wbr>invoice</code>](#pyxecm_customizer.sap.SAP.cancel_supplier_invoice) |

### Inventory Management

| Object | Create | Read | Update | Delete | Actions |
| --- | --- | --- | --- | --- | --- |
| Goods movement (material document) <br><code>SAPGoods<wbr>Movement…</code> | [<code>create_<wbr>goods_<wbr>movement</code>](#pyxecm_customizer.sap.SAP.create_goods_movement) | [<code>get_<wbr>goods_<wbr>movements</code>](#pyxecm_customizer.sap.SAP.get_goods_movements)<br>[<code>iter_<wbr>goods_<wbr>movements</code>](#pyxecm_customizer.sap.SAP.iter_goods_movements)<br>[<code>get_<wbr>goods_<wbr>movement_<wbr>items</code>](#pyxecm_customizer.sap.SAP.get_goods_movement_items)<br>[<code>iter_<wbr>goods_<wbr>movement_<wbr>items</code>](#pyxecm_customizer.sap.SAP.iter_goods_movement_items)<br>[<code>get_<wbr>goods_<wbr>movement</code>](#pyxecm_customizer.sap.SAP.get_goods_movement) | - | - | [<code>cancel_<wbr>goods_<wbr>movement</code>](#pyxecm_customizer.sap.SAP.cancel_goods_movement) |
| Material stock <br><code>SAPMaterial<wbr>Stock…</code> | - | [<code>get_<wbr>material_<wbr>stock</code>](#pyxecm_customizer.sap.SAP.get_material_stock)<br>[<code>iter_<wbr>material_<wbr>stock</code>](#pyxecm_customizer.sap.SAP.iter_material_stock) | - | - | - |

### Production

| Object | Create | Read | Update | Delete | Actions |
| --- | --- | --- | --- | --- | --- |
| Planned order <br><code>SAPPlanned<wbr>Order…</code> | [<code>create_<wbr>planned_<wbr>order</code>](#pyxecm_customizer.sap.SAP.create_planned_order) | [<code>get_<wbr>planned_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.get_planned_orders)<br>[<code>iter_<wbr>planned_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.iter_planned_orders)<br>[<code>get_<wbr>planned_<wbr>order</code>](#pyxecm_customizer.sap.SAP.get_planned_order) | [<code>update_<wbr>planned_<wbr>order</code>](#pyxecm_customizer.sap.SAP.update_planned_order) | [<code>delete_<wbr>planned_<wbr>order</code>](#pyxecm_customizer.sap.SAP.delete_planned_order) | [<code>schedule_<wbr>planned_<wbr>order</code>](#pyxecm_customizer.sap.SAP.schedule_planned_order)<br>[<code>convert_<wbr>planned_<wbr>order</code>](#pyxecm_customizer.sap.SAP.convert_planned_order) |
| Production order <br><code>SAPProduction<wbr>Order…</code> | [<code>create_<wbr>production_<wbr>order</code>](#pyxecm_customizer.sap.SAP.create_production_order)<br>[<code>create_<wbr>production_<wbr>order_<wbr>from_<wbr>planned_<wbr>order</code>](#pyxecm_customizer.sap.SAP.create_production_order_from_planned_order) | [<code>get_<wbr>production_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.get_production_orders)<br>[<code>iter_<wbr>production_<wbr>orders</code>](#pyxecm_customizer.sap.SAP.iter_production_orders)<br>[<code>get_<wbr>production_<wbr>order</code>](#pyxecm_customizer.sap.SAP.get_production_order) | [<code>update_<wbr>production_<wbr>order</code>](#pyxecm_customizer.sap.SAP.update_production_order) | - | [<code>change_<wbr>production_<wbr>order_<wbr>status</code>](#pyxecm_customizer.sap.SAP.change_production_order_status) |

### Warranty

| Object | Create | Read | Update | Delete | Actions |
| --- | --- | --- | --- | --- | --- |
| Warranty claim <br><code>SAPWarranty<wbr>Claim…</code> | [<code>create_<wbr>warranty_<wbr>claim</code>](#pyxecm_customizer.sap.SAP.create_warranty_claim) | [<code>get_<wbr>warranty_<wbr>claims</code>](#pyxecm_customizer.sap.SAP.get_warranty_claims)<br>[<code>iter_<wbr>warranty_<wbr>claims</code>](#pyxecm_customizer.sap.SAP.iter_warranty_claims)<br>[<code>get_<wbr>warranty_<wbr>claim</code>](#pyxecm_customizer.sap.SAP.get_warranty_claim) | [<code>update_<wbr>warranty_<wbr>claim</code>](#pyxecm_customizer.sap.SAP.update_warranty_claim)<br>[<code>update_<wbr>warranty_<wbr>claim_<wbr>version</code>](#pyxecm_customizer.sap.SAP.update_warranty_claim_version) | - | [<code>process_<wbr>customer_<wbr>claim</code>](#pyxecm_customizer.sap.SAP.process_customer_claim)<br>[<code>process_<wbr>supplier_<wbr>claim</code>](#pyxecm_customizer.sap.SAP.process_supplier_claim)<br>[<code>start_<wbr>supplier_<wbr>process_<wbr>from_<wbr>customer_<wbr>claim</code>](#pyxecm_customizer.sap.SAP.start_supplier_process_from_customer_claim)<br>[<code>confirm_<wbr>customer_<wbr>return_<wbr>parts</code>](#pyxecm_customizer.sap.SAP.confirm_customer_return_parts) |

### Logistics Master Data

| Object | Create | Read | Update | Delete | Actions |
| --- | --- | --- | --- | --- | --- |
| Product (material) <br><code>SAPProduct…</code> | [<code>create_<wbr>product</code>](#pyxecm_customizer.sap.SAP.create_product)<br>[<code>create_<wbr>product_<wbr>plant</code>](#pyxecm_customizer.sap.SAP.create_product_plant)<br>[<code>create_<wbr>product_<wbr>storage_<wbr>location</code>](#pyxecm_customizer.sap.SAP.create_product_storage_location)<br>[<code>create_<wbr>product_<wbr>valuation</code>](#pyxecm_customizer.sap.SAP.create_product_valuation) | [<code>get_<wbr>products</code>](#pyxecm_customizer.sap.SAP.get_products)<br>[<code>iter_<wbr>products</code>](#pyxecm_customizer.sap.SAP.iter_products)<br>[<code>get_<wbr>product</code>](#pyxecm_customizer.sap.SAP.get_product) | [<code>update_<wbr>product</code>](#pyxecm_customizer.sap.SAP.update_product)<br>[<code>update_<wbr>product_<wbr>description</code>](#pyxecm_customizer.sap.SAP.update_product_description)<br>[<code>update_<wbr>product_<wbr>plant</code>](#pyxecm_customizer.sap.SAP.update_product_plant) | [<code>delete_<wbr>product</code>](#pyxecm_customizer.sap.SAP.delete_product) | [<code>undelete_<wbr>product</code>](#pyxecm_customizer.sap.SAP.undelete_product) |
| Material BOM <br><code>SAPMaterial<wbr>BOM…</code> | [<code>create_<wbr>material_<wbr>bom</code>](#pyxecm_customizer.sap.SAP.create_material_bom)<br>[<code>create_<wbr>material_<wbr>bom_<wbr>item</code>](#pyxecm_customizer.sap.SAP.create_material_bom_item) | [<code>get_<wbr>material_<wbr>boms</code>](#pyxecm_customizer.sap.SAP.get_material_boms)<br>[<code>iter_<wbr>material_<wbr>boms</code>](#pyxecm_customizer.sap.SAP.iter_material_boms) | [<code>update_<wbr>material_<wbr>bom</code>](#pyxecm_customizer.sap.SAP.update_material_bom) | [<code>delete_<wbr>material_<wbr>bom_<wbr>item</code>](#pyxecm_customizer.sap.SAP.delete_material_bom_item) | - |
| Production version <br><code>SAPProduction<wbr>Version…</code> | - | [<code>get_<wbr>production_<wbr>versions</code>](#pyxecm_customizer.sap.SAP.get_production_versions)<br>[<code>iter_<wbr>production_<wbr>versions</code>](#pyxecm_customizer.sap.SAP.iter_production_versions)<br>[<code>get_<wbr>production_<wbr>version</code>](#pyxecm_customizer.sap.SAP.get_production_version) | - | - | - |
| Work center <br><code>SAPWork<wbr>Center…</code> | - | [<code>get_<wbr>work_<wbr>centers</code>](#pyxecm_customizer.sap.SAP.get_work_centers)<br>[<code>iter_<wbr>work_<wbr>centers</code>](#pyxecm_customizer.sap.SAP.iter_work_centers)<br>[<code>get_<wbr>work_<wbr>center</code>](#pyxecm_customizer.sap.SAP.get_work_center) | - | - | - |
| Equipment <br><code>SAPEquipment…</code> | [<code>create_<wbr>equipment</code>](#pyxecm_customizer.sap.SAP.create_equipment) | [<code>get_<wbr>equipments</code>](#pyxecm_customizer.sap.SAP.get_equipments)<br>[<code>iter_<wbr>equipments</code>](#pyxecm_customizer.sap.SAP.iter_equipments)<br>[<code>get_<wbr>equipment</code>](#pyxecm_customizer.sap.SAP.get_equipment) | [<code>update_<wbr>equipment</code>](#pyxecm_customizer.sap.SAP.update_equipment) | [<code>delete_<wbr>equipment</code>](#pyxecm_customizer.sap.SAP.delete_equipment) | [<code>undelete_<wbr>equipment</code>](#pyxecm_customizer.sap.SAP.undelete_equipment)<br>[<code>install_<wbr>equipment</code>](#pyxecm_customizer.sap.SAP.install_equipment)<br>[<code>dismantle_<wbr>equipment</code>](#pyxecm_customizer.sap.SAP.dismantle_equipment) |
| Functional location <br><code>SAPFunctional<wbr>Location…</code> | [<code>create_<wbr>functional_<wbr>location</code>](#pyxecm_customizer.sap.SAP.create_functional_location) | [<code>get_<wbr>functional_<wbr>locations</code>](#pyxecm_customizer.sap.SAP.get_functional_locations)<br>[<code>iter_<wbr>functional_<wbr>locations</code>](#pyxecm_customizer.sap.SAP.iter_functional_locations)<br>[<code>get_<wbr>functional_<wbr>location</code>](#pyxecm_customizer.sap.SAP.get_functional_location) | [<code>update_<wbr>functional_<wbr>location</code>](#pyxecm_customizer.sap.SAP.update_functional_location) | [<code>delete_<wbr>functional_<wbr>location</code>](#pyxecm_customizer.sap.SAP.delete_functional_location) | [<code>undelete_<wbr>functional_<wbr>location</code>](#pyxecm_customizer.sap.SAP.undelete_functional_location)<br>[<code>install_<wbr>functional_<wbr>location</code>](#pyxecm_customizer.sap.SAP.install_functional_location)<br>[<code>dismantle_<wbr>functional_<wbr>location</code>](#pyxecm_customizer.sap.SAP.dismantle_functional_location) |
| Business partner <br><code>SAPBusiness<wbr>Partner…</code> | [<code>create_<wbr>business_<wbr>partner</code>](#pyxecm_customizer.sap.SAP.create_business_partner)<br>[<code>create_<wbr>business_<wbr>partner_<wbr>role</code>](#pyxecm_customizer.sap.SAP.create_business_partner_role) | [<code>get_<wbr>business_<wbr>partners</code>](#pyxecm_customizer.sap.SAP.get_business_partners)<br>[<code>iter_<wbr>business_<wbr>partners</code>](#pyxecm_customizer.sap.SAP.iter_business_partners)<br>[<code>get_<wbr>business_<wbr>partner</code>](#pyxecm_customizer.sap.SAP.get_business_partner) | [<code>update_<wbr>business_<wbr>partner</code>](#pyxecm_customizer.sap.SAP.update_business_partner)<br>[<code>update_<wbr>business_<wbr>partner_<wbr>address</code>](#pyxecm_customizer.sap.SAP.update_business_partner_address) | - | - |
| Customer <br><code>SAPCustomer…</code> | [<code>create_<wbr>customer_<wbr>sales_<wbr>area</code>](#pyxecm_customizer.sap.SAP.create_customer_sales_area)<br>[<code>create_<wbr>customer_<wbr>company</code>](#pyxecm_customizer.sap.SAP.create_customer_company) | [<code>get_<wbr>customers</code>](#pyxecm_customizer.sap.SAP.get_customers)<br>[<code>iter_<wbr>customers</code>](#pyxecm_customizer.sap.SAP.iter_customers)<br>[<code>get_<wbr>customer</code>](#pyxecm_customizer.sap.SAP.get_customer) | - | - | - |
| Supplier <br><code>SAPSupplier…</code> | [<code>create_<wbr>supplier_<wbr>purchasing_<wbr>org</code>](#pyxecm_customizer.sap.SAP.create_supplier_purchasing_org)<br>[<code>create_<wbr>supplier_<wbr>company</code>](#pyxecm_customizer.sap.SAP.create_supplier_company) | [<code>get_<wbr>suppliers</code>](#pyxecm_customizer.sap.SAP.get_suppliers)<br>[<code>iter_<wbr>suppliers</code>](#pyxecm_customizer.sap.SAP.iter_suppliers)<br>[<code>get_<wbr>supplier</code>](#pyxecm_customizer.sap.SAP.get_supplier) | - | - | - |

### Organizational Units and Finance

| Object | Create | Read | Update | Delete | Actions |
| --- | --- | --- | --- | --- | --- |
| Plant <br><code>SAPPlant…</code> | - | [<code>get_<wbr>plants</code>](#pyxecm_customizer.sap.SAP.get_plants)<br>[<code>iter_<wbr>plants</code>](#pyxecm_customizer.sap.SAP.iter_plants)<br>[<code>get_<wbr>plant</code>](#pyxecm_customizer.sap.SAP.get_plant) | - | - | - |
| Storage location <br><code>SAPStorage<wbr>Location…</code> | - | [<code>get_<wbr>storage_<wbr>locations</code>](#pyxecm_customizer.sap.SAP.get_storage_locations)<br>[<code>iter_<wbr>storage_<wbr>locations</code>](#pyxecm_customizer.sap.SAP.iter_storage_locations)<br>[<code>get_<wbr>storage_<wbr>location</code>](#pyxecm_customizer.sap.SAP.get_storage_location) | - | - | - |
| Company code <br><code>SAPCompany<wbr>Code…</code> | - | [<code>get_<wbr>company_<wbr>codes</code>](#pyxecm_customizer.sap.SAP.get_company_codes)<br>[<code>iter_<wbr>company_<wbr>codes</code>](#pyxecm_customizer.sap.SAP.iter_company_codes)<br>[<code>get_<wbr>company_<wbr>code</code>](#pyxecm_customizer.sap.SAP.get_company_code) | - | - | - |
| Sales organization <br><code>SAPSales<wbr>Organization…</code> | - | [<code>get_<wbr>sales_<wbr>organizations</code>](#pyxecm_customizer.sap.SAP.get_sales_organizations)<br>[<code>iter_<wbr>sales_<wbr>organizations</code>](#pyxecm_customizer.sap.SAP.iter_sales_organizations)<br>[<code>get_<wbr>sales_<wbr>organization</code>](#pyxecm_customizer.sap.SAP.get_sales_organization) | - | - | - |
| Purchasing organization <br><code>SAPPurchasing<wbr>Organization…</code> | - | [<code>get_<wbr>purchasing_<wbr>organizations</code>](#pyxecm_customizer.sap.SAP.get_purchasing_organizations)<br>[<code>iter_<wbr>purchasing_<wbr>organizations</code>](#pyxecm_customizer.sap.SAP.iter_purchasing_organizations)<br>[<code>get_<wbr>purchasing_<wbr>organization</code>](#pyxecm_customizer.sap.SAP.get_purchasing_organization) | - | - | - |
| Cost center <br><code>SAPCost<wbr>Center…</code> | - | [<code>get_<wbr>cost_<wbr>centers</code>](#pyxecm_customizer.sap.SAP.get_cost_centers)<br>[<code>iter_<wbr>cost_<wbr>centers</code>](#pyxecm_customizer.sap.SAP.iter_cost_centers)<br>[<code>get_<wbr>cost_<wbr>center</code>](#pyxecm_customizer.sap.SAP.get_cost_center) | - | - | - |
| Profit center <br><code>SAPProfit<wbr>Center…</code> | - | [<code>get_<wbr>profit_<wbr>centers</code>](#pyxecm_customizer.sap.SAP.get_profit_centers)<br>[<code>iter_<wbr>profit_<wbr>centers</code>](#pyxecm_customizer.sap.SAP.iter_profit_centers)<br>[<code>get_<wbr>profit_<wbr>center</code>](#pyxecm_customizer.sap.SAP.get_profit_center) | - | - | - |
| G/L account <br><code>SAPGLAccount…</code> | - | [<code>get_<wbr>gl_<wbr>accounts</code>](#pyxecm_customizer.sap.SAP.get_gl_accounts)<br>[<code>iter_<wbr>gl_<wbr>accounts</code>](#pyxecm_customizer.sap.SAP.iter_gl_accounts)<br>[<code>get_<wbr>gl_<wbr>account</code>](#pyxecm_customizer.sap.SAP.get_gl_account) | - | - | - |

## Connection, authentication and checks

| Method | Purpose |
| --- | --- |
| [`check_odata_apis`](#pyxecm_customizer.sap.SAP.check_odata_apis) | Check per OData service whether it is activated and authorized - see [SAP APIs](sap-apis.md#verifying-activation) |
| [`check_oauth_token_endpoint`](#pyxecm_customizer.sap.SAP.check_oauth_token_endpoint)<br>[`check_principal_propagation`](#pyxecm_customizer.sap.SAP.check_principal_propagation) | Check the setup of principal propagation - see [Testing the setup](sap-authentication.md#testing-the-setup) |
| [`get_saml_assertion`](#pyxecm_customizer.sap.SAP.get_saml_assertion)<br>[`get_oauth_access_token`](#pyxecm_customizer.sap.SAP.get_oauth_access_token)<br>[`get_oauth_access_token_for_user`](#pyxecm_customizer.sap.SAP.get_oauth_access_token_for_user)<br>[`oauth_token_url`](#pyxecm_customizer.sap.SAP.oauth_token_url) | Get an SAP access token for a user - see [SAP Authentication / SSO](sap-authentication.md#usage) |
| [`granted_scopes`](#pyxecm_customizer.sap.SAP.granted_scopes) | The OAuth scopes (OData services) the user's access token was granted |
| [`last_error`](#pyxecm_customizer.sap.SAP.last_error)<br>[`log_error`](#pyxecm_customizer.sap.SAP.log_error) | The error of the calling thread's last failed call |
| [`get_odata_entity_type`](#pyxecm_customizer.sap.SAP.get_odata_entity_type) | The `$metadata` of an entity set (properties, types, keys) - used to validate changes |
| [`do_request`](#pyxecm_customizer.sap.SAP.do_request)<br>[`service_url`](#pyxecm_customizer.sap.SAP.service_url)<br>[`csrf_token`](#pyxecm_customizer.sap.SAP.csrf_token)<br>[`request_session`](#pyxecm_customizer.sap.SAP.request_session)<br>[`parse_request_response`](#pyxecm_customizer.sap.SAP.parse_request_response) | Low-level OData requests - for APIs that have no method yet |
| [`call`](#pyxecm_customizer.sap.SAP.call) | Call an RFC function module or BAPI via PyRFC - see [RFC channel](sap-apis.md#rfc-channel-sapcall) |

## Look up a workspace's SAP business object

Use [`get_business_object`](#pyxecm_customizer.sap.SAP.get_business_object) to retrieve the SAP
object referenced by a workspace payload's business object connection:

```python
connection = workspace["business_objects"][0]  # A connection to the SAP system
sap_object = sap.get_business_object(
    bo_type=connection["bo_type"],
    bo_id=connection["bo_id"],
)
if sap_object is not None:
    print("The SAP object exists:", sap_object)
```

The method calls the OData getter of the business object type and returns its typed response
model unchanged, including its default expanded related data. It supports the BOR types in
`SAP_BUSINESS_OBJECT_TYPES` in `sap_models.py`. IDs use SAP's internal format (leading zeros and
concatenated composite keys); single-field IDs also accept the external format. For example,
`BUS2017` with `49000001232026` looks up material document `4900000123` in year `2026`.

`None` means the lookup did not succeed, **not necessarily that the object is absent**:
unsupported types, malformed IDs, authorization errors, and connectivity failures also return
`None`. Inspect `sap.last_error` or use `pyxecm.capture_errors()` to distinguish failures. This
method does not change workspace payload processing automatically.

## PDF documents

SAP returns the PDF of a billing document with
[`get_billing_document_pdf`](#pyxecm_customizer.sap.SAP.get_billing_document_pdf) - if output
management is configured. For systems without it, and for documents that have no PDF API,
`pyxecm_customizer.sap_forms` renders PDFs from the OData data in the style of the SAP standard
forms (logo, address window, item table, totals, page numbers; A4 or US letter depending on the
recipient's country): billing documents, sales orders and contracts, outbound deliveries,
purchase orders and contracts, maintenance orders, production orders and goods movements.

```python
from pyxecm_customizer.sap_forms import render_billing_document_pdf

billing_document = sap.get_billing_document("90000001")
customer = sap.get_customer(billing_document.payer)  # business partner with addresses
pdf = render_billing_document_pdf(billing_document, customer=customer, logo="logo.png")
```

It needs the `forms` extra; without ReportLab, the module can be imported, but the render
functions raise `RuntimeError`.

## Reference

::: pyxecm_customizer.sap

::: pyxecm_customizer.sap_forms

# SAP S/4HANA APIs Required by This Module

This page lists everything that must be activated/authorized in the target S/4HANA
system for the `pyxecm_customizer.sap.SAP` class to work. It is a checklist for
S/4HANA Basis/Gateway administrators, derived from the service registry in
[`sap.py`](sap.md) (`SAP_ODATA_SERVICES`).

Use `SAP.check_odata_apis()` to verify the status of all services below against a
live system - it reports exactly which of the steps below is still missing per service.

## General activation steps (apply to every OData service)

1. **`/IWFND/MAINT_SERVICE`** (OData V2) or **`/IWFND/V4_ADMIN`** (OData V4): activate /
   publish the service for the relevant backend system alias.
   - V2: "Add Service" -> backend system alias (e.g. `LOCAL`) -> technical service
     name (e.g. `API_MAINTENANCEORDER`) -> "Get Services" -> select the version(s)
     (e.g. `0001`, `0002`) -> "Add Selected Services".
   - V4: "Publish Service Groups" for the service group (e.g. `API_PURCHASEORDER_2`).
2. **`SICF`**: the ICF node of the service must be active (`/sap/opu/odata/sap/<service>`
   for V2, `/sap/opu/odata4` for V4).
3. **`PFCG`**: the calling user needs authorization object **`S_SERVICE`** for the
   service (role menu entry of type `IWSG`), plus the business authorizations for the
   underlying transaction (e.g. as for `IW31` to create maintenance orders).
4. **`/IWFND/GW_CLIENT`**: `GET /sap/opu/odata/sap/<service>/$metadata` (or the V4
   equivalent) should return HTTP 200 as a smoke test.

Troubleshooting: `/IWFND/ERROR_LOG`, `SU53`, and the system log (`SM21`).

### "No System Alias found for Service" (`/IWFND/CM_COS/064`, HTTP 500)

`SAP.check_odata_apis()` reports `state=error` with a message like `[/IWFND/CM_COS/064]
No System Alias found for Service '<technical name>' and user '<user>'` when a service
has been registered in `/IWFND/MAINT_SERVICE` but has no backend system alias assigned to
it - a step further than "not activated" (403), but still unusable. This typically happens
when the service was added through a route other than the normal "Add Service" wizard in
step 1 above (e.g. transport import, or a different Fiori content activation report), which
skips the alias assignment. To fix it in `/IWFND/MAINT_SERVICE`:

1. Filter/find the entry for the technical service name (e.g. `API_MAINTNOTIFICATION`) in
   the service list.
2. Select its row and open the **"SAP System Alias"** assignment dialog (toolbar button /
   context menu on the row - exact label depends on the SAP_GWFND release).
3. Add the same backend system alias that the already-working services use (e.g. `LOCAL` -
   check the alias of `API_MAINTENANCEORDER`, which is active, for the correct value in this
   system) and mark it as default if prompted.
4. Save, then re-run `SAP.check_odata_apis()` to confirm the service moved to `active`.

## OData services

The **BO Type** column lists the SAP business object type (BOR object type, transaction
`SWO1`) of the main entity of each service - e.g. the type to use for business workspaces
and business object references in Extended ECM. All types were checked in the S/4HANA
reference system; "-" means there is no BOR object type for the entity.

The business object types that business workspaces are typically linked to are also available
in code: `SAP_BUSINESS_OBJECT_TYPES` in `pyxecm_customizer.sap_models` (name and key structure),
and `get_sap_key_fields()` converts a business object ID (SAP's internal format, e.g.
`"49000001232026"`) into the key fields the OData APIs expect (e.g. `("4900000123", "2026")`).

¹ `BUS0008001` is the BOR object type "Plant storage area" - the storage location of a plant.

### Plant Maintenance

| Service                      | BO Type   | Version        | Entity Sets                                                  | Purpose                                                |
| ---------------------------- | --------- | -------------- | ------------------------------------------------------------ | ------------------------------------------------------ |
| `API_MAINTENANCEORDER`       | `BUS2007` | V2 (`;v=0002`) | `MaintenanceOrder`, `MaintenanceOrderOperation`              | Create / Read / Update maintenance orders              |
| `API_MAINTNOTIFICATION`      | `BUS2038` | V2             | `MaintenanceNotification`, `MaintenanceNotificationItem`     | Create / Read / Update maintenance notifications       |
| `API_MAINTORDERCONFIRMATION` | `BUS2128` | V2             | `MaintOrderConfirmation`                                     | Create / Read / Cancel maintenance order confirmations |
| `API_MAINTENANCEPLAN`        | `BUS1020` | V2             | `MaintenancePlan`, `MaintenancePlanCycle`, `MaintenanceItem` | Create / Read / Update / Schedule maintenance plans    |
| `API_MAINTENANCETASKLIST`    | `BUS1019` | V4             | `MaintenanceTaskList`, `MaintenanceTaskListOperation`        | Create / Read / Update maintenance task lists          |

### Sales

| Service                       | BO Type   | Version        | Entity Sets                                      | Purpose                                                                   |
| ----------------------------- | --------- | -------------- | ------------------------------------------------ | ------------------------------------------------------------------------- |
| `API_SALES_ORDER_SRV`         | `BUS2032` | V2             | `A_SalesOrder`, `A_SalesOrderItem`               | Create / Read / Update / Delete sales orders                              |
| `API_SALES_CONTRACT_SRV`      | `BUS2034` | V2             | `A_SalesContract`, `A_SalesContractItem`         | Create / Read / Update / Delete sales contracts                           |
| `API_CREDIT_MEMO_REQUEST_SRV` | `BUS2094` | V2             | `A_CreditMemoRequest`, `A_CreditMemoRequestItem` | Create / Read / Update / Delete / Approve credit memo requests            |
| `API_DEBIT_MEMO_REQUEST_SRV`  | `BUS2096` | V2             | `A_DebitMemoRequest`, `A_DebitMemoRequestItem`   | Create / Read / Update / Delete debit memo requests                       |
| `API_OUTBOUND_DELIVERY_SRV`   | `LIKP`    | V2 (`;v=0002`) | `A_OutbDeliveryHeader`, `A_OutbDeliveryItem`     | Create / Read / Update / Delete outbound deliveries, picking, goods issue |

### Billing

| Service                            | BO Type                      | Version | Entity Sets                                                | Purpose                                                                                |
| ---------------------------------- | ---------------------------- | ------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `API_BILLING_DOCUMENT_SRV`         | `VBRK` (abstract: `BUS2037`) | V2      | `A_BillingDocument`, `A_BillingDocumentItem`               | Read / Cancel billing documents (customer invoices, credit / debit memos), get the PDF |
| `API_BILLING_DOCUMENT_REQUEST_SRV` | -                            | V2      | `A_BillingDocumentRequest`, `A_BillingDocumentRequestItem` | Read / Delete / Reject billing document requests (external billing)                    |

### Purchasing

| Service                            | BO Type                     | Version        | Entity Sets                                                                                         | Purpose                                                                    |
| ---------------------------------- | --------------------------- | -------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `API_PURCHASECONTRACT_PROCESS_SRV` | `BUS2014`                   | V2             | `A_PurchaseContract`, `A_PurchaseContractItem`                                                      | Create / Read / Update purchase contracts                                  |
| `API_PURCHASEREQUISITION_2`        | `BUS2105` (item: `BUS2009`) | V4             | `PurchaseReqn`, `PurchaseReqnItem`, `PurchaseReqnAcctAssgmt`                                        | Create / Read / Update purchase requisitions                               |
| `API_PURCHASEORDER_2`              | `BUS2012`                   | V4             | `PurchaseOrder`, `PurchaseOrderItem`, `PurchaseOrderScheduleLine`, `PurchaseOrderAccountAssignment` | Create / Read / Update / Delete purchase orders                            |
| `API_SUPPLIERINVOICE_PROCESS_SRV`  | `BUS2081`                   | V2             | `A_SupplierInvoice`, `A_SuplrInvcItemPurOrdRef`, `A_SupplierInvoiceItemGLAcct`                      | Create / Read / Delete / Cancel / Release supplier invoices                |
| `API_INBOUND_DELIVERY_SRV`         | `BUS2015`                   | V2 (`;v=0002`) | `A_InbDeliveryHeader`, `A_InbDeliveryItem`                                                          | Create / Read / Update / Delete inbound deliveries, putaway, goods receipt |

### Inventory Management

| Service                     | BO Type   | Version | Entity Sets                                          | Purpose                                                          |
| --------------------------- | --------- | ------- | ---------------------------------------------------- | ---------------------------------------------------------------- |
| `API_MATERIAL_DOCUMENT_SRV` | `BUS2017` | V2      | `A_MaterialDocumentHeader`, `A_MaterialDocumentItem` | Create / Read / Cancel goods movements (material documents)      |
| `API_MATERIAL_STOCK_SRV`    | -         | V2      | `A_MaterialStock`, `A_MatlStkInAcctMod`              | Read the stock per plant, storage location, batch and stock type |

### Production

| Service                      | BO Type   | Version | Entity Sets                                                                        | Purpose                                                        |
| ---------------------------- | --------- | ------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `API_PLANNEDORDER`           | `BUS2004` | V4      | `PlannedOrderHeader`                                                               | Create / Read / Update / Delete / Schedule planned orders      |
| `API_PRODUCTION_ORDER_2_SRV` | `BUS2005` | V2      | `A_ProductionOrder_2`, `A_ProductionOrderOperation_2`, `A_ProductionOrderStatus_2` | Create / Read / Update / Convert / Status of production orders |

### Master Data (read-only)

| Service                              | BO Type                                        | Version | Entity Sets                                           | Purpose                    |
| ------------------------------------ | ---------------------------------------------- | ------- | ----------------------------------------------------- | -------------------------- |
| `API_PLANT_2`                        | `BUS0008`                                      | V4      | `Plant`                                               | Plants                     |
| `API_STORAGELOCATION_SRV`            | `BUS0008001` ¹                                 | V2      | `StorageLocation`                                     | Storage locations          |
| `API_PRODUCT_SRV`                    | `BUS1001006` (generic: `BUS1001`)              | V2      | `A_Product`, `A_ProductPlant`, `A_ProductDescription` | Products / materials       |
| `API_PRODUCTION_VERSION`             | -                                              | V4      | `ProductionVersion`                                   | Production versions        |
| `API_WORK_CENTERS`                   | `BUS0011`                                      | V2      | `A_WorkCenters`                                       | Work centers               |
| `API_EQUIPMENT`                      | `EQUI`                                         | V2      | `Equipment`                                           | Equipment master           |
| `API_FUNCTIONALLOCATION`             | `BUS0010`                                      | V2      | `FunctionalLocation`                                  | Functional location master |
| `API_BUSINESS_PARTNER`               | `BUS1006` (customer: `KNA1`, supplier: `LFA1`) | V2      | `A_BusinessPartner`, `A_BusinessPartnerRole`          | Business partners          |
| `API_COMPANYCODE_SRV`                | `BUS0002`                                      | V2      | `A_CompanyCode`                                       | Company codes              |
| `API_SALESORGANIZATION_SRV`          | `BUS0006`                                      | V2      | `A_SalesOrganization`                                 | Sales organizations        |
| `API_PURCHASINGORGANIZATION`         | `BUS0007`                                      | V4      | `A_PurchasingOrganization`                            | Purchasing organizations   |
| `API_COSTCENTER_SRV`                 | `BUS0012`                                      | V2      | `A_CostCenter`                                        | Cost centers               |
| `API_PROFITCENTER_SRV`               | `BUS0015`                                      | V2      | `A_ProfitCenter`                                      | Profit centers             |
| `API_GLACCOUNTINCHARTOFACCOUNTS_SRV` | `BUS3006`                                      | V2      | `A_GLAccountInChartOfAccounts`                        | G/L accounts               |

## RFC channel (`SAP.call()`)

For RFC/BAPI based calls (used e.g. for custom Z function modules or standard BAPIs
such as `BAPI_USER_CREATE1`), OData activation is not relevant. Instead:

- **`SM59`**: an RFC destination (or direct application server connection) must be
  reachable with the configured `ashost`/`mshost`, `sysnr`/`group`, `client` and user.
- **`SU01`/`PFCG`**: the RFC user needs authorization object **`S_RFC`** for the
  function group of every RFC/BAPI it calls, and the usual business authorizations
  for the underlying transaction (e.g. `SU01` authorizations for `BAPI_USER_*`).
- **Gateway**: the RFC gateway (`SMGW`) must allow the connection (`gw/acl_mode`,
  `secinfo`/`reginfo` ACLs) if calling from outside the SAP network.
- The **SAP NW RFC SDK** (proprietary, from SAP) and the `pyrfc` Python package
  must be installed on the machine running this module (`pip install "pyxecm[sap]"`
  only installs `pyrfc`, not the SDK itself).

## Verifying activation

```python
from pyxecm_customizer.sap import SAP

sap = SAP(username="...", password="...", base_url="https://s4.example.com:44300", ...)
statuses = sap.check_odata_apis()
for name, status in statuses.items():
    print(name, status.state, status.hint)
```

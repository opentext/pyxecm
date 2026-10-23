# SAP

The `SAP` class talks to SAP S/4HANA via OData REST APIs and remote function calls (RFC).
OData needs no extra packages. Optional features need these extras:

```bash
pip install "pyxecm[sap]"   # RFC calls via PyRFC (also needs the SAP NW RFC SDK)
pip install "pyxecm[saml]"  # principal propagation - see SAP Authentication / SSO
```

See [SAP Authentication / SSO](sap-authentication.md) for calling SAP as the individual
user and [SAP APIs that must be activated](sap-apis.md) for the required OData services.

## Look up a workspace's SAP business object

Use `SAP.get_business_object(bo_type, bo_id)` to retrieve the SAP object referenced
by a workspace payload's business object connection:

```python
connection = workspace["business_objects"][0]  # A connection to the SAP system
sap_object = sap.get_business_object(
    bo_type=connection["bo_type"],
    bo_id=connection["bo_id"],
)
if sap_object is not None:
    print("The SAP object exists:", sap_object)
```

The method uses `match` / `case` to call the corresponding OData getter and returns
its typed response model unchanged, including its default expanded related data.
It supports the BOR types in `SAP_BUSINESS_OBJECT_TYPES` in `sap_models.py`.
IDs use SAP's internal format (leading zeros and concatenated composite keys);
single-field IDs also accept the external format. For example, `BUS2017` with
`49000001232026` looks up material document `4900000123` in year `2026`.

`None` means the lookup did not succeed, **not necessarily that the object is
absent**: unsupported types, malformed IDs, authorization errors, and connectivity
failures also return `None`. Inspect `sap.last_error` or use
`pyxecm.capture_errors()` to distinguish failures. This method does not change
workspace payload processing automatically.

::: pyxecm_customizer.sap

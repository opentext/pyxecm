# SAP

The `SAP` class talks to SAP S/4HANA via OData REST APIs and remote function calls (RFC).
OData needs no extra packages. Optional features need these extras:

```bash
pip install "pyxecm[sap]"   # RFC calls via PyRFC (also needs the SAP NW RFC SDK)
pip install "pyxecm[saml]"  # principal propagation - see SAP Authentication / SSO
```

See [SAP Authentication / SSO](sap-authentication.md) for calling SAP as the individual
user and [SAP APIs that must be activated](sap-apis.md) for the required OData services.

::: pyxecm_customizer.sap

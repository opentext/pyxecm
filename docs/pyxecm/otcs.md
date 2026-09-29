# Content Server (OTCS)

The `OTCS` class is the client for the OpenText Content Server REST API. It covers nodes (folders,
documents, ...), business workspaces, categories and attributes, users and groups, permissions,
records management and more.

## Authentication

`OTCS.authenticate()` tries the available credentials in this order:

1. OTDS token (`otds_token`)
2. OTDS ticket (`otds_ticket`)
3. Username and password

```python
from pyxecm import OTCS

otcs = OTCS(
    protocol="https",
    hostname="otcs.domain.tld",
    port=443,
    username="admin",
    password="********",
    base_path="/cs/cs",
)
otcs.authenticate()
```

::: pyxecm.otcs

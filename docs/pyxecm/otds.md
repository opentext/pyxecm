# Directory Services (OTDS)

The `OTDS` class is the client for the OpenText Directory Services REST API. It manages
partitions, users, groups, OAuth clients, resources, access roles, licenses and more.

## Authentication

`OTDS.authenticate()` selects the grant type automatically if none is given:

- If `username` and `password` are set, the `password` grant is used.
- If only `client_id` and `client_secret` are set, the `client_credentials` grant is used.

```python
from pyxecm import OTDS

otds = OTDS(
    protocol="https",
    hostname="otds.domain.tld",
    port=443,
    username="admin",
    password="********",
)
otds.authenticate()
```

::: pyxecm.otds

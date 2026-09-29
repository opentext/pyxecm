# Getting Started

## Installation

`pyxecm` is published on [PyPI](https://pypi.org/project/pyxecm/). The base package contains the
REST API client classes. Additional features are available as optional extras:

| Extra        | Installs support for                                                        |
| ------------ | --------------------------------------------------------------------------- |
| *(none)*     | REST API client classes (`OTCS`, `OTDS`, `OTAC`, ...)                       |
| `customizer` | The payload-driven Customizer (Kubernetes, browser automation, HCL / YAML). |
| `api`        | The Customizer REST API server (FastAPI).                                   |
| `magic`      | MIME type detection via `python-magic`.                                     |
| `sap`        | SAP RFC calls via `pyrfc`.                                                  |

```bash
# REST API client classes only
pip install pyxecm

# Customizer
pip install "pyxecm[customizer]"

# Customizer REST API server (requires the customizer extra)
pip install "pyxecm[api,customizer]"
```

The Customizer uses [Playwright](https://playwright.dev/python/) for browser automation. If you
use browser automation, install the browser binaries once after installing the package. The
default browser is `webkit`; set the environment variable `BROWSER` to `chromium` or `firefox`
to use a different one:

```bash
playwright install webkit
```

## Command line tools

The package installs the following commands:

| Command                   | Description                                                                    |
| ------------------------- | ------------------------------------------------------------------------------ |
| `pyxecm-customizer`       | Runs the Customizer for a single payload file (`.yaml`, `.tf` or `.tfvars`).   |
| `pyxecm-api`              | Starts the Customizer REST API server (default: `http://localhost:8000/api`).  |

## Using the library

Each OpenText product is represented by its own class. All classes follow the same pattern:
create an object with the connection details, authenticate, then call its methods.

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

if not otcs.authenticate():
    raise SystemExit("Authentication with Content Server failed")

# Get the items in the Enterprise Workspace (node ID 2000):
nodes = otcs.get_subnodes(parent_node_id=2000)
```

Most methods return the parsed JSON response of the REST API as a `dict`, or `None` if the
call failed. Most methods log errors instead of raising exceptions, so always check the return
value.

All classes accept an optional `logger` argument. Pass your own `logging.Logger` to integrate
the log output into your application:

```python
import logging

from pyxecm import OTCS

logging.basicConfig(level=logging.INFO)

otcs = OTCS(
    protocol="https",
    hostname="otcs.domain.tld",
    port=443,
    username="admin",
    password="********",
    logger=logging.getLogger("my-app"),
)
```

## Using the Customizer

The Customizer configures an OpenText environment from a declarative payload file.

1. Configure the connection settings as environment variables or in a `.env` file.
   See [Customizer Settings](pyxecm-customizer/settings.md).
2. Describe the objects to create in a payload file.
   See [Payload Syntax](pyxecm-customizer/payload-syntax.md).
3. Run the Customizer:

    ```bash
    pyxecm-customizer payload.yaml
    ```


# PYXECM

A Python library to interact with the OpenText Content Management REST APIs.

- Product API documentation: [OpenText Developer](https://developer.opentext.com/ce/products/extendedecm)
- Documentation of this package: [opentext.github.io/pyxecm](https://opentext.github.io/pyxecm/)

## Quick start - Library usage

Install the latest version from pypi:

```bash
pip install pyxecm
```

### Start using the package libraries

Example usage of the OTCS class. More details can be found in the [documentation](https://opentext.github.io/pyxecm/pyxecm/otcs/):

```python
from pyxecm import OTCS

otcs_object = OTCS(
    protocol="https",
    hostname="otcs.domain.tld",
    port=443,
    public_url="otcs.domain.tld",
    username="admin",
    password="********",
    base_path="/cs/llisapi.dll",
)

otcs_object.authenticate()

nodes = otcs_object.get_subnodes(2000)

for node in nodes["results"]:
    print(node["data"]["properties"]["id"], node["data"]["properties"]["name"])
```

## Quick start - Customizer usage

- Create an `.env` file as described in [Customizer Settings](https://opentext.github.io/pyxecm/pyxecm-customizer/settings/#sample-env).
- Create a payload file that defines what the Customizer should do, as described in [Payload Syntax](https://opentext.github.io/pyxecm/pyxecm-customizer/payload-syntax/).

```bash
pip install "pyxecm[customizer]"

pyxecm-customizer PAYLOAD.yaml   # or PAYLOAD.tfvars
```

## Quick start - API

- Install pyxecm with the `api` and `customizer` extras
- Launch the REST API server
- Access the Customizer API at [http://localhost:8000/api](http://localhost:8000/api)

```bash
pip install "pyxecm[api,customizer]"

pyxecm-api
```

## Disclaimer

!!! quote ""
    Copyright © 2024-2026 Open Text Corporation, All Rights Reserved.
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

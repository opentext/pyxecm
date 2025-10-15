# PYXECM

A python library to interact with Opentext Content Mangement REST API.
The product API documentation is available on [OpenText Developer](https://developer.opentext.com/ce/products/extendedecm)
Detailed documentation of this package is available [here](https://opentext.github.io/pyxecm/).

## Quick start - Library usage

Install the latest version from pypi:

```bash
pip install pyxecm
```

### Start using the package libraries

example usage of the OTCS class, more details can be found in the docs:

```python
from pyxecm import OTCS

otcs_object = OTCS(
    protocol="https",
    hostname="otcs.domain.tld",
    port="443",
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

- Create an `.env` file as described here: [sample-environment-variables](customizerapisettings/#sample-environment-variables)
- Create an payload file to define what the customizer should do, as described here [payload-syntax](payload-syntax)

```bash
pip install pyxecm[customizer]

pyxecm-customizer PAYLOAD.tfvars/PAYLOAD.yaml
```

## Quick start - API 

- Install pyxecm with api and customizer dependencies
- Launch the Rest API server
- Access the Customizer API at [http://localhost:8000/api](http://localhost:8000/api)

```bash
pip install pyxecm[api,customizer]

pyxecm-api
```

## Disclaimer


Copyright © 2025 Open Text Corporation, All Rights Reserved.
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

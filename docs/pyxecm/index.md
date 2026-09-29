# pyxecm

The `pyxecm` package contains one client class per OpenText product. Each class wraps the REST API
of its product and handles authentication, paging and error logging.

| Class                             | Product                                          |
| --------------------------------- | ------------------------------------------------ |
| [`OTAC`](otac.md)                 | Archive Center                                   |
| [`AVTS`](avts.md)                 | Aviator Search                                   |
| [`OTCS`](otcs.md)                 | Content Server                                   |
| [`CoreShare`](coreshare.md)       | Core Share                                       |
| [`OTDS`](otds.md)                 | Directory Services                               |
| [`OTIV`](otiv.md)                 | Intelligent Viewing                              |
| [`OTMM`](otmm.md)                 | Media Management                                 |
| [`OTPD`](otpd.md)                 | PowerDocs                                        |

All classes can be imported directly from the package:

```python
from pyxecm import OTCS, OTDS
```

The [helper classes](helper.md) contain utilities that are used by the product classes and by
the Customizer, for example for tabular data processing and XML handling.

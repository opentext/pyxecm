# Customizer

The Customizer configures an OpenText environment from a declarative payload file (YAML or
Terraform / HCL). It connects to the product services (OTDS, OTCS, OTAC, ...) using the
[Customizer Settings](settings.md) and then processes the [payload](payload-syntax.md) section
by section.

Run it from the command line:

```bash
pyxecm-customizer payload.yaml
```

Settings in the `customizerSettings` section of the payload override the environment settings.

::: pyxecm_customizer.customizer

::: pyxecm_customizer.exceptions

::: pyxecm_customizer.log

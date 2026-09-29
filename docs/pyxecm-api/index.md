# Customizer API

The Customizer API is a [FastAPI](https://fastapi.tiangolo.com/) server that runs the Customizer
and exposes endpoints to upload and manage payloads, check the status of payload processing and
run maintenance tasks.

Start the server with:

```bash
pip install "pyxecm[api,customizer]"
pyxecm-api
```

The interactive OpenAPI documentation is available at `http://localhost:8000/api` once the server is
running. See [API Settings](settings.md) for the available configuration options.

## Application

::: pyxecm_api.app

## Authentication

::: pyxecm_api.auth.router
::: pyxecm_api.auth.models
::: pyxecm_api.auth.functions

## Common

::: pyxecm_api.common.router
::: pyxecm_api.common.models
::: pyxecm_api.common.metrics
::: pyxecm_api.common.functions

## Maintenance

::: pyxecm_api.v1_maintenance.router
::: pyxecm_api.v1_maintenance.models
::: pyxecm_api.v1_maintenance.functions

## OTCS

::: pyxecm_api.v1_otcs.router
::: pyxecm_api.v1_otcs.functions

## Payload

::: pyxecm_api.v1_payload.router
::: pyxecm_api.v1_payload.models
::: pyxecm_api.v1_payload.functions

## Terminal

::: pyxecm_api.terminal.router

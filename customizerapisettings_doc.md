31-Mar-2025 14:04:34 INFO [CustomizerAPI.k8s] [MainThread] Failed to load in-cluster config
## `CUSTOMIZER_API_TOKEN`

*Optional*, default value: `None`

Optional token that can be specified that has access to the Customizer API, bypassing the OTDS authentication.

## `CUSTOMIZER_BIND_ADDRESS`

*Optional*, default value: `0.0.0.0`

Interface to bind the Customizer API.

## `CUSTOMIZER_BIND_PORT`

*Optional*, default value: `8000`

Port to bind the Customizer API to

## `CUSTOMIZER_IMPORT_PAYLOAD`

*Optional*, default value: `False`

## `CUSTOMIZER_PAYLOAD`

*Optional*, default value: `/payload/payload.yml.gz.b64`

Path to a single Payload file to be loaded.

## `CUSTOMIZER_PAYLOAD_DIR`

*Optional*, default value: `/payload-external/`

Path to a directory of Payload files. All files in this directory will be loaded in alphabetical order and dependencies will be added automatically on the previous object. So all payload in this folder will be processed sequentially in alphabetical oder.

## `CUSTOMIZER_PAYLOAD_DIR_OPTIONAL`

*Optional*, default value: `/payload-optional/`

Path of Payload files to be loaded. No additional logic for dependencies will be applied, they need to be managed within the payloadSetitings section of each payload. See -> payloadOptions in the Payload Syntax documentation.

## `CUSTOMIZER_TEMP_DIR`

*Optional*, default value: `/var/folders/yk/vkrlb78s2_3cjt4g0kxmm0f80000gn/T/customizer`

location of the temp folder. Used for temporary files during the payload execution

## `CUSTOMIZER_LOGLEVEL`

*Optional*, default value: `INFO`

### Possible values

`INFO`, `DEBUG`, `WARNING`, `ERROR`

## `CUSTOMIZER_LOGFOLDER`

*Optional*, default value: `/var/folders/yk/vkrlb78s2_3cjt4g0kxmm0f80000gn/T/customizer`

Logfolder for Customizer logfiles

## `CUSTOMIZER_LOGFILE`

*Optional*, default value: `customizer.log`

Logfile for Customizer API. This logfile also contains the execution of every payload.

## `CUSTOMIZER_NAMESPACE`

*Optional*, default value: `default`

Namespace to use for otxecm resource lookups

## `CUSTOMIZER_MAINTENANCE_MODE`

*Optional*, default value: `True`

Automatically enable and disable the maintenance mode during payload deployments.

## `CUSTOMIZER_TRUSTED_ORIGINS`

*Optional*, default value: `['http://localhost', 'http://localhost:5173', 'http://localhost:8080', 'https://manager.develop.terrarium.cloud', 'https://manager.terrarium.cloud']`

## `OTDS_PROTOCOL`

*Optional*, default value: `http`

## `OTDS_HOSTNAME`

*Optional*, default value: `otds`

## `OTDS_SERVICE_PORT_OTDS`

*Optional*, default value: `80`

## `OTDS_URL`

*Optional*, default value: `None`

## `CUSTOMIZER_METRICS`

*Optional*, default value: `True`

Enable or disable the /metrics endpoint for Prometheus

## `CUSTOMIZER_VICTORIALOGS_HOST`

*Optional*, default value: ``

Hostname of the VictoriaLogs Server

## `CUSTOMIZER_VICTORIALOGS_PORT`

*Optional*, default value: `9428`

Port of the VictoriaLogs Server


## `CUST_LOG_FILE`

*Optional*, default value: `/var/folders/yk/vkrlb78s2_3cjt4g0kxmm0f80000gn/T/customizing.log`

Logfile for Customizer execution

## `CUST_SETTINGS_DIR`

*Optional*, default value: `/settings/`

Location where AdminSettings xml files are located

## `CUST_PAYLOAD_DIR`

*Optional*, default value: `/payload/`

## `CUST_PAYLOAD`

*Optional*, default value: `annotation=NoneType required=False default='/payload/' deprecated=Truepayload.yaml`

Location of the payload file. File can be in YAML or in Terraform TFVARS Format.

## `CUST_PAYLOAD_GZ`

*Optional*, default value: `annotation=NoneType required=False default='/payload/' deprecated=Truepayload.yml.gz.b64`

Location of the payload file in gz format, unzip format must bei either YAML or Terraform TFVARS.

## `CUST_PAYLOAD_EXTERNAL`

*Optional*, default value: `/payload-external/`

## `CUST_TARGET_FOLDER_NICKNAME`

*Optional*, default value: `deployment`

Nickname of folder to upload payload and log files

## `CUST_RM_SETTINGS_DIR`

*Optional*, default value: `/settings/`

## `STOP_ON_ERROR`

*Optional*, default value: `False`

Stop the payload processing when an error during the transport package deployment occours. This can be useful for debugging, to identify missing dependencies.

## `PLACEHOLDER_VALUES`

*Optional*, default value: `{}`

## `PROFILING`

*Optional*, default value: `False`

 Profiling can only be enabled when using the CustomizerAPI. Switch to enable python profiling using pyinstrument. Result is a html file showing the execution of payload broken down into functions and their duration. The files are located in the logdir. Profiling is disabled by default.

## `CPROFILING`

*Optional*, default value: `False`

 Profiling can only be enabled when using the CustomizerAPI. Switch to enable python profiling using cProfile. Result is a log file with the cProfile results, as well as a dump of the profiling session. The files are located in the logdir. The files are located in the logdir. Profilig is disabled by default.

## `OTDS__USERNAME`

*Optional*, default value: `admin`

Username for the OTDS admin user

## `OTDS__PASSWORD`

*Optional*, default value: `None`

Password for the OTDS admin user

## `OTDS__TICKET`

*Optional*, default value: `None`

Ticket for the OTDS admin user

## `OTDS__ADMIN_PARTITION`

*Optional*, default value: `otds.admin`

Name of the default Partition in OTDS

## `OTDS__ENABLE_AUDIT`

*Optional*, default value: `True`

Enable the OTDS Audit

## `OTDS__DISABLE_PASSWORD_POLICY`

*Optional*, default value: `True`

Switch to disable the default OTDS password policy

## `OTDS__URL`

*Optional*, default value: `None`

URL of the OTDS service

## `OTDS__URL_INTERNAL`

*Optional*, default value: `None`

Internal URL of the OTDS service

## `OTDS__BIND_PASSWORD`

*Optional*, default value: `None`

Password for the OTDS bind user to LDAP

## `OTCS__USERNAME`

*Optional*, default value: `admin`

Username for the OTCS admin user

## `OTCS__PASSWORD`

*Optional*, default value: `None`

Password for the OTCS admin user

## `OTCS__BASE_PATH`

*Optional*, default value: `/cs/cs`

Base path of the OTCS installation

## `OTCS__URL`

*Optional*, default value: `None`

URL of the OTCS service

## `OTCS__URL_FRONTEND`

*Optional*, default value: `None`

URL of the OTCS frontend service, if not specified, it will be set to the same value as url

## `OTCS__URL_BACKEND`

*Optional*, default value: `None`

URL of the OTCS backend service, if not specified, it will be set to the same value as url

## `OTCS__PARTITION`

*Optional*, default value: `Content Server Members`

Name of the default Partition in OTDS

## `OTCS__RESOURCE_NAME`

*Optional*, default value: `cs`

Name of the OTCS resource in OTDS

## `OTCS__MAINTENANCE_MODE`

*Optional*, default value: `False`

Enable/Disable maintenance mode during payload processing.

## `OTCS__LICENSE_FEATURE`

*Optional*, default value: `X3`

Default license feature to be added to Users in OTDS

## `OTCS__DOWNLOAD_DIR`

*Optional*, default value: `/var/folders/yk/vkrlb78s2_3cjt4g0kxmm0f80000gn/T`

temporary download directory for payload processing

## `OTCS__FEME_URI`

*Optional*, default value: `ws://feme:4242`

URL of the FEME endpoint

## `OTCS__UPDATE_ADMIN_USER`

*Optional*, default value: `True`

Update the OTCS Admin user and rename to Terrarium Admin.

## `OTCS__UPLOAD_CONFIG_FILES`

*Optional*, default value: `True`

Upload the configuration files of the payload to OTCS.

## `OTCS__UPLOAD_STATUS_FILES`

*Optional*, default value: `True`

Upload the status files of the payload to OTCS.

## `OTCS__UPLOAD_LOG_FILE`

*Optional*, default value: `True`

Upload the log file of the payload to OTCS.

## `OTAC__ENABLED`

*Optional*, default value: `False`

Enable/Disable OTAC integration

## `OTAC__USERNAME`

*Optional*, default value: `dsadmin`

Admin account for OTAC

## `OTAC__PASSWORD`

*Optional*, default value: `None`

Password of the Admin Account

## `OTAC__URL`

*Optional*, default value: `None`

URL of the OTAC service

## `OTAC__URL_INTERNAL`

*Optional*, default value: `None`

Internal URL of the OTAC service

## `OTAC__KNOWN_SERVER`

*Optional*, default value: ``

Known OTAC servers to add to OTAC

## `OTPD__ENABLED`

*Optional*, default value: `False`

Enable/Disable the OTPD integration

## `OTPD__PASSWORD`

*Optional*, default value: ``

Password of the API user to configure OTPD

## `OTPD__URL`

*Optional*, default value: `None`

URL of the OTPD service

## `OTPD__DB_IMPORTFILE`

*Optional*, default value: ``

Path to the OTPD import file

## `OTPD__TENANT`

*Optional*, default value: `Successfactors`

## `OTIV__ENABLED`

*Optional*, default value: `False`

Enable/Disable the OTIV integration

## `OTIV__LICENSE_FILE`

*Optional*, default value: `/payload/otiv-license.lic`

Path to the OTIV license file.

## `OTIV__LICENSE_FEATURE`

*Optional*, default value: `FULLTIME_USERS_REGULAR`

Name of the license feature.

## `OTIV__PRODUCT_NAME`

*Optional*, default value: `Viewing`

Name of the product for the license.

## `OTIV__PRODUCT_DESCRIPTION`

*Optional*, default value: `OpenText Intelligent Viewing`

Description of the product for the license.

## `OTIV__RESOURCE_NAME`

*Optional*, default value: `iv`

Name of the resource for OTIV

## `K8S__ENABLED`

*Optional*, default value: `True`

Enable/Disable the K8s integration

## `K8S__KUBECONFIG_FILE`

*Optional*, default value: `/Users/kgatzweiler/.kube/config`

Path to the kubeconfig file

## `K8S__NAMESPACE`

*Optional*, default value: `default`

Name of the namespace

## `K8S__STS_OTAWP`

*Optional*, default value: `appworks`

Name of the OTAWP statefulset

## `K8S__CM_OTAWP`

*Optional*, default value: `appworks-config-ymls`

Name of the OTAWP configmap

## `K8S__POD_OTPD`

*Optional*, default value: `otpd-0`

Name of the OTPD pod

## `K8S__POD_OTAC`

*Optional*, default value: `otac-0`

Name of the OTAC pod

## `K8S__STS_OTCS_FRONTEND`

*Optional*, default value: `otcs-frontend`

Name of the OTCS-FRONTEND statefulset

## `K8S__STS_OTCS_FRONTEND_REPLICAS`

*Optional*, default value: `None`

## `K8S__STS_OTCS_ADMIN`

*Optional*, default value: `otcs-admin`

Name of the OTCS-ADMIN statefulset

## `K8S__STS_OTCS_ADMIN_REPLICAS`

*Optional*, default value: `None`

## `K8S__INGRESS_OTXECM`

*Optional*, default value: `otxecm-ingress`

Name of the otxecm ingress

## `K8S__MAINTENANCE_SERVICE_NAME`

*Optional*, default value: `otxecm-customizer`

## `K8S__MAINTENANCE_SERVICE_PORT`

*Optional*, default value: `5555`

## `OTAWP__ENABLED`

*Optional*, default value: `False`

Enable/Disable the OTAWP integration

## `OTAWP__USERNAME`

*Optional*, default value: `sysadmin`

Username of the OTAWP Admin user

## `OTAWP__PASSWORD`

*Optional*, default value: `None`

Password of the OTAWP Admin user

## `OTAWP__LICENSE_FILE`

*Optional*, default value: `/payload/otawp-license.lic`

Path to the OTAWP license file.

## `OTAWP__PRODUCT_NAME`

*Optional*, default value: `APPWORKS_PLATFORM`

Name of the Product for the license

## `OTAWP__PRODUCT_DESCRIPTION`

*Optional*, default value: `OpenText Appworks Platform`

Product desciption to be added in OTDS.

## `OTAWP__RESOURCE_NAME`

*Optional*, default value: `awp`

Name of the Resource for OTAWP

## `OTAWP__ACCESS_ROLE_NAME`

*Optional*, default value: `Access to awp`

Name of the Access Role for OTAWP

## `OTAWP__PUBLIC_PROTOCOL`

*Optional*, default value: `https`

Protocol of the public OTAWP endpoint.

## `OTAWP__PUBLIC_URL`

*Optional*, default value: ``

Public URL address of the OTAWP service

## `OTAWP__PORT`

*Optional*, default value: `8080`

## `OTAWP__PROTOCOL`

*Optional*, default value: `http`

Protocol for the OTAWP service.

## `M365__PASSWORD`

*Optional*, default value: ``

Password of the M365 tenant Admin.

## `M365__ENABLED`

*Optional*, default value: `False`

Enable/Disable the Microsoft 365 integration.

## `M365__TENANT_ID`

*Optional*, default value: ``

TennantID of the Microsoft 365 tenant

## `M365__CLIENT_ID`

*Optional*, default value: ``

Client ID for the Microsoft 365 tenant.

## `M365__CLIENT_SECRET`

*Optional*, default value: ``

Client Secret for the Microsoft 365 tenant.

## `M365__DOMAIN`

*Optional*, default value: `O365_DOMAIN`

Base domain for the Microsoft 365 tenant.

## `M365__SKU_ID`

*Optional*, default value: `c7df2760-2c81-4ef7-b578-5b5392b571df`

## `M365__UPDATE_TEAMS_APP`

*Optional*, default value: `False`

Automatically update the Teams App to the latest version if already exists.

## `M365__TEAMS_APP_NAME`

*Optional*, default value: `OpenText Extended ECM`

Name of the Teams App

## `M365__TEAMS_APP_EXTERNAL_ID`

*Optional*, default value: `dd4af790-d8ff-47a0-87ad-486318272c7a`

External ID of the Teams App

## `M365__SHAREPOINT_APP_ROOT_SITE`

*Optional*, default value: ``

## `M365__SHAREPOINT_APP_CLIENT_ID`

*Optional*, default value: ``

## `M365__SHAREPOINT_APP_CLIENT_SECRET`

*Optional*, default value: ``

## `M365__AZURE_STORAGE_ACCOUNT`

*Optional*, default value: `None`

## `M365__AZURE_STORAGE_ACCESS_KEY`

*Optional*, default value: `None`

## `M365__AZURE_FUNCTION_URL`

*Optional*, default value: `None`

## `M365__AZURE_FUNCTION_URL_NOTIFICATION`

*Optional*, default value: `None`

## `CORESHARE__ENABLED`

*Optional*, default value: `False`

Enable/Disable Core Share integration

## `CORESHARE__USERNAME`

*Optional*, default value: ``

Admin username for Core Share

## `CORESHARE__PASSWORD`

*Optional*, default value: `None`

Admin username for Core Share

## `CORESHARE__BASE_URL`

*Optional*, default value: `https://core.opentext.com`

Base URL of the Core Share Instance

## `CORESHARE__SSO_URL`

*Optional*, default value: `https://sso.core.opentext.com`

OTDS URL of the Core Share Instance

## `CORESHARE__CLIENT_ID`

*Optional*, default value: ``

Client ID for the Core Share integration

## `CORESHARE__CLIENT_SECRET`

*Optional*, default value: ``

Client Secret for the Core Share integration

## `AVIATOR__ENABLED`

*Optional*, default value: `False`

Content Aviator enabled

## `AVTS__ENABLED`

*Optional*, default value: `False`

Enable Aviator Search configuration

## `AVTS__USERNAME`

*Optional*, default value: ``

Admin username for Aviator Search

## `AVTS__PASSWORD`

*Optional*, default value: ``

Admin password for Aviator Search

## `AVTS__OTDS_URL`

*Optional*, default value: `None`

URL of the OTDS

## `AVTS__CLIENT_ID`

*Optional*, default value: ``

OTDS Client ID for Aviator Search

## `AVTS__CLIENT_SECRET`

*Optional*, default value: ``

OTDS Client Secret for Aviator Search

## `AVTS__BASE_URL`

*Optional*, default value: `None`

## `OTMM__ENABLED`

*Optional*, default value: `False`

Enable/Disable the OTMM integration

## `OTMM__USERNAME`

*Optional*, default value: ``

Username of the API user to connect to OTMM

## `OTMM__PASSWORD`

*Optional*, default value: `None`

Password of the API user to connect to OTMM

## `OTMM__CLIENT_ID`

*Optional*, default value: `None`

Client ID of the API user to connect to OTMM

## `OTMM__CLIENT_SECRET`

*Optional*, default value: `None`

Client Secret of the API user to connect to OTMM

## `OTMM__URL`

*Optional*, default value: `None`

URL of the OTMM service


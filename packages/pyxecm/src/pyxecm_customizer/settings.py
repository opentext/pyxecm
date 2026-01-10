"""Settings for Customizer execution."""

import os
import tempfile
from typing import Self

from pydantic import AliasChoices, BaseModel, Field, HttpUrl, SecretStr, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)


class CustomizerSettingsOTDS(BaseModel):
    """Class for OTDS related settings."""

    username: str = Field(default="admin", description="Username for the OTDS admin user")
    password: SecretStr = Field(default=None, description="Password for the OTDS admin user")
    client_id: str | None = Field(None, description="Client ID for the OTDS admin user")
    client_secret: SecretStr | None = Field(None, description="Client Secret for the OTDS admin user")
    ticket: str | None = Field(None, description="Ticket for the OTDS admin user")
    admin_partition: str = Field(default="otds.admin", description="Name of the admin partition in OTDS")
    enable_audit: bool = Field(default=True, description="Enable the OTDS Audit")
    disable_password_policy: bool = Field(
        default=True,
        description="Switch to disable the default OTDS password policy",
    )

    url: HttpUrl | None = Field(default=None, description="URL of the OTDS service")
    url_internal: HttpUrl | None = Field(default=None, description="Internal URL of the OTDS service")

    bind_password: SecretStr = Field(default=None, description="Password for the OTDS bind user to LDAP")

    @model_validator(mode="after")
    def fallback(self) -> Self:
        """Fallback implementation to read the URL from the environment."""

        if not self.url:
            self.url = HttpUrl(
                os.environ.get("OTDS_PUBLIC_PROTOCOL", "http") + "://" + os.environ.get("OTDS_PUBLIC_URL", "otds"),
            )

        # Set url_internal to the same value as url if only that one is set
        elif not self.url_internal:
            self.url_internal = self.url

        if not self.url_internal:
            self.url_internal = HttpUrl(
                os.environ.get("OTDS_PUBLIC_PROTOCOL", "http")
                + "://"
                + os.environ.get("OTDS_HOSTNAME", "otds")
                + ":"
                + os.environ.get("OTDS_SERVICE_PORT", "80"),
            )

        self.password = SecretStr(os.environ.get("OTDS_PASSWORD")) if self.password is None else self.password
        self.bind_password = (
            SecretStr(os.environ.get("BIND_PASSWORD")) if self.bind_password is None else self.bind_password
        )

        return self


class CustomizerSettingsOTCS(BaseModel):
    """Class for OTCS related settings."""

    # Content Server Endpoints:
    username: str = Field(default="admin", description="Username for the OTCS admin user")
    password: SecretStr = Field(default=None, description="Password for the OTCS admin user")
    base_path: str = Field(default="/cs/cs", description="Base path of the OTCS installation")
    support_path: str = Field(default="/cssupport", description="Support path of the OTCS installation")
    url: HttpUrl | None = Field(default=None, description="URL of the OTCS service")
    url_frontend: HttpUrl | None = Field(
        default=None,
        description="URL of the OTCS frontend service, if not specified, it will be set to the same value as url",
    )
    url_backend: HttpUrl | None = Field(
        default=None,
        description="URL of the OTCS backend service, if not specified, it will be set to the same value as url",
    )

    partition: str = Field(default="Content Server Members", description="Name of the default Partition in OTDS")
    resource_name: str = Field(default="cs", description="Name of the OTCS resource in OTDS")

    maintenance_mode: bool = Field(
        default=False,
        description="Enable/Disable maintenance mode during payload processing.",
    )
    license_feature: str = Field(default="X3", description="Default license feature to be added to Users in OTDS")
    download_dir: str = Field(
        default=tempfile.gettempdir(),
        description="temporary download directory for payload processing",
    )

    # FEME endpoint for additional embedding supporting Content Aviator:
    feme_uri: str = Field(default="ws://feme:4242", description="URL of the FEME endpoint")

    # Add configuration options for Customizer behaviour
    update_admin_user: bool = Field(
        default=True,
        description="Update the OTCS Admin user and rename to Terrarium Admin.",
    )
    upload_config_files: bool = Field(
        default=True,
        description="Upload the configuration files of the payload to OTCS.",
    )
    upload_status_files: bool = Field(default=True, description="Upload the status files of the payload to OTCS.")
    upload_log_file: bool = Field(default=True, description="Upload the log file of the payload to OTCS.")

    @model_validator(mode="after")
    def fallback(self) -> Self:
        """Fallback implementation to read the URL from the environment."""

        if not self.url:
            self.url = HttpUrl(
                os.environ.get("OTCS_PUBLIC_PROTOCOL", "https")
                + "://"
                + os.environ.get("OTCS_PUBLIC_URL", "otcs.public-url.undefined")
                + ":"
                + os.environ.get("OTCS_SERVICE_PORT_OTCS", "8080"),
            )
        else:
            if not self.url_frontend:
                self.url_frontend = self.url

            if not self.url_backend:
                self.url_backend = self.url

        if not self.url_frontend:
            self.url_frontend = HttpUrl(
                os.environ.get("OTCS_PROTOCOL", "http")
                + "://"
                + os.environ.get("OTCS_HOSTNAME_FRONTEND", "otcs-frontend"),
            )

        if not self.url_backend:
            self.url_backend = HttpUrl(
                os.environ.get("OTCS_PROTOCOL", "http")
                + "://"
                + os.environ.get("OTCS_HOSTNAME", "otcs-admin-0")
                + ":"
                + os.environ.get("OTCS_SERVICE_PORT_OTCS", "8080"),
            )

        self.password = SecretStr(os.environ.get("OTCS_PASSWORD", "")) if self.password is None else self.password

        return self


class CustomizerSettingsOTAC(BaseModel):
    """Class for OTAC related settings."""

    enabled: bool = Field(
        default=False,
        description="Enable/Disable OTAC integration",
    )
    username: str = Field(
        default="dsadmin",
        description="Admin account for OTAC",
    )
    password: SecretStr | None = Field(default=None, description="Password of the Admin Account")
    url: HttpUrl | None = Field(default=None, description="URL of the OTAC service")
    url_internal: HttpUrl | None = Field(default=None, description="Internal URL of the OTAC service")

    known_server: str = Field(default="", description="Known OTAC servers to add to OTAC")

    @model_validator(mode="after")
    def fallback(self) -> Self:
        """Fallback implementation to read the URL from the environment."""

        if not self.url:
            self.url = HttpUrl(
                os.environ.get("OTAC_PROTOCOL", "https")
                + "://"
                + os.environ.get("OTAC_PUBLIC_URL", "otac-0")
                + ":"
                + os.environ.get("OTAC_SERVICE_PORT", "443"),
            )

        if not self.url_internal:
            self.url_internal = HttpUrl(
                os.environ.get("OTAC_PROTOCOL", "http")
                + "://"
                + os.environ.get("OTAC_SERVICE_HOST", "otac-0")
                + ":"
                + os.environ.get("OTAC_SERVICE_PORT", "8080"),
            )

        self.password = SecretStr(os.environ.get("OTAC_PASSWORD", "")) if self.password is None else self.password

        return self


class CustomizerSettingsOTPD(BaseModel):
    """Class for OTPD related settings."""

    enabled: bool = Field(default=False, description="Enable/Disable the OTPD integration")
    username: str = Field(
        default="powerdocsapiuser",
        description="Username of the API user to configure OTPD",
        validation_alias=AliasChoices("username", "user"),
    )
    password: SecretStr = Field(default=SecretStr(""), description="Password of the API user to configure OTPD")
    url: HttpUrl | None = Field(default=None, description="URL of the OTPD service")

    db_importfile: str = Field(default="", description="Path to the OTPD import file")
    tenant: str = Field(default="Successfactors")

    @model_validator(mode="after")
    def fallback(self) -> Self:
        """Fallback implementation to read the URL from the environment."""

        if not self.url:
            self.url = HttpUrl(
                os.environ.get("OTPD_PROTOCOL", "http")
                + "://"
                + os.environ.get("OTPD_SERVICE_HOST", "otpd")
                + ":"
                + os.environ.get("OTPD_SERVICE_PORT", "8080"),
            )

        return self


class CustomizerSettingsOTIV(BaseModel):
    """Class for OTIV related settings."""

    enabled: bool = Field(default=False, description="Enable/Disable the OTIV integration")
    license_file: str = Field(default="/payload/otiv-license.lic", description="Path to the OTIV license file.")
    license_feature: str = Field(default="FULLTIME_USERS_REGULAR", description="Name of the license feature.")
    product_name: str = Field(default="Viewing", description="Name of the product for the license.")
    product_description: str = Field(
        default="OpenText Intelligent Viewing",
        description="Description of the product for the license.",
    )
    resource_name: str = Field(default="iv", description="Name of the resource for OTIV")


class CustomizerSettingsOTMM(BaseModel):
    """Class for OTMM related settings."""

    enabled: bool = Field(default=False, description="Enable/Disable the OTMM integration")
    username: str = Field(default="", description="Username of the API user to connect to OTMM")
    password: SecretStr = Field(default=None, description="Password of the API user to connect to OTMM")
    client_id: str | None = Field(default=None, description="Client ID of the API user to connect to OTMM")
    client_secret: str | None = Field(default=None, description="Client Secret of the API user to connect to OTMM")
    url: HttpUrl | None = Field(default=None, description="URL of the OTMM service")


class CustomizerSettingsK8S(BaseModel):
    """Class for K8s related settings."""

    enabled: bool = Field(default=True, description="Enable/Disable the K8s integration")
    kubeconfig_file: str = Field(
        default=os.path.expanduser("~/.kube/config"),
        description="Path to the kubeconfig file",
    )
    namespace: str = Field(default="default", description="Name of the namespace")

    sts_otawp: str = Field(default="appworks", description="Name of the OTAWP statefulset")
    cm_otawp: str = Field(default="appworks-config-ymls", description="Name of the OTAWP configmap")
    pod_otpd: str = Field(default="otpd-0", description="Name of the OTPD pod")
    pod_otac: str = Field(default="otac-0", description="Name of the OTAC pod")
    sts_otcs_frontend: str = Field(default="otcs-frontend", description="Name of the OTCS-FRONTEND statefulset")
    sts_otcs_frontend_replicas: int = Field(None)
    sts_otcs_admin: str = Field(default="otcs-admin", description="Name of the OTCS-ADMIN statefulset")
    sts_otcs_admin_replicas: int = Field(default=None)
    sts_otcs_da: str = Field(default="otcs-da", description="Name of the OTCS-DA statefulset")
    sts_otcs_da_replicas: int = Field(default=None)
    ingress_otxecm: str = Field(default="otxecm-ingress", description="Name of the otxecm ingress")

    maintenance_service_name: str = Field(default="customizer")
    maintenance_service_port: int = Field(default=5555)


class CustomizerSettingsOTAWP(BaseModel):
    """Class for OTAWP related settings."""

    enabled: bool = Field(default=False, description="Enable/Disable the OTAWP integration")
    username: str = Field(
        default="sysadmin",
        description="Username of the OTAWP Admin user",
    )
    password: SecretStr = Field(default=None, description="Password of the OTAWP Admin user")
    organization: str = Field(default="system", description="The name of the organization (kind of tenant in AppWorks)")
    license_file: str = Field(default="/payload/otawp-license.lic", description="Path to the OTAWP license file.")
    product_name: str = Field(default="APPWORKS_PLATFORM", description="Name of the Product for the license")
    product_description: str = Field(
        default="OpenText Appworks Platform",
        description="Product desciption to be added in OTDS.",
    )
    resource_name: str = Field(default="awp", description="Name of the Resource for OTAWP")
    access_role_name: str = Field(default="Access to awp", description="Name of the Access Role for OTAWP")
    public_protocol: str = Field(default="https", description="Protocol of the public OTAWP endpoint.")
    public_url: str = Field("", description="Public URL address of the OTAWP service")
    port: int = int(os.environ.get("OTAWP_SERVICE_PORT", "8080"))
    protocol: str = Field(default="http", description="Protocol for the OTAWP service.")


class CustomizerSettingsM365(BaseModel):
    """Class for M365 related settings."""

    username: str = Field(
        default="",
        description="Username of the M365 tenant Admin.",
        validation_alias=AliasChoices("username", "user"),
    )
    password: SecretStr = Field(default="", description="Password of the M365 tenant Admin.")
    enabled: bool = Field(default=False, description="Enable/Disable the Microsoft 365 integration.")
    tenant_id: str = Field(default="", description="TennantID of the Microsoft 365 tenant")
    client_id: str = Field(default="", description="Client ID for the Microsoft 365 tenant.")
    client_secret: str = Field(default="", description="Client Secret for the Microsoft 365 tenant.")
    domain: str = Field(default="O365_DOMAIN", description="Base domain for the Microsoft 365 tenant.")
    sku_id: str = Field(default="c7df2760-2c81-4ef7-b578-5b5392b571df")
    update_teams_app: bool = Field(
        default=False,
        description="Automatically update the Teams App to the latest version if already exists.",
    )
    teams_app_name: str = Field(default="OpenText Extended ECM", description="Name of the Teams App")
    teams_app_external_id: str = Field(
        default="dd4af790-d8ff-47a0-87ad-486318272c7a",
        description="External ID of the Teams App",
    )
    sharepoint_app_root_site: str = Field(default="")
    sharepoint_app_client_id: str = Field(default="")
    sharepoint_app_client_secret: str = Field(default="")

    azure_storage_account: str | None = Field(default=None)
    azure_storage_access_key: str | None = Field(default=None)
    azure_function_url: str | None = Field(default=None)
    azure_function_url_notification: str | None = Field(default=None)


class CustomizerSettingsCoreShare(BaseModel):
    """Class for Core Share related settings."""

    enabled: bool = Field(default=False, description="Enable/Disable Core Share integration")
    username: str = Field(default="", description="Admin username for Core Share")
    password: SecretStr = Field(default=None, description="Admin username for Core Share")
    base_url: str = Field(default="https://core.opentext.com", description="Base URL of the Core Share Instance")
    sso_url: str = Field(default="https://sso.core.opentext.com", description="OTDS URL of the Core Share Instance")
    client_id: str = Field(default="", description="Client ID for the Core Share integration")
    client_secret: str = Field(default="", description="Client Secret for the Core Share integration")


class CustomizerSettingsAviator(BaseModel):
    """Class for Aviator related settings."""

    enabled: bool = Field(default=False, description="Content Aviator enabled")
    oauth_client: str = Field(default="", description="OAuth Client ID for Content Aviator")
    oauth_secret: str = Field(default="", description="OAuth Client Secret for Content Aviator")
    chat_svc_url: HttpUrl = Field(
        default=HttpUrl("http://csai-chat-svc:3000"), description="Chat Service URL for Content Aviator"
    )
    embed_svc_url: HttpUrl = Field(
        default=HttpUrl("http://csai-embed-svc:3000"), description="Embed Service URL for Content Aviator"
    )
    studio_url: HttpUrl = Field(
        default=HttpUrl("http://csai-aviator-studio"), description="Service URL for Aviator Studio"
    )


class CustomizerSettingsKnowledgeDiscovery(BaseModel):
    """Class for Knowledge Discovery related settings."""

    enabled: bool = Field(default=False, description="Knowledge Discovery enabled")
    url: HttpUrl | None = Field(default=None, description="URL of the Nifi Server")
    username: str = Field(default="admin", description="Admin username for Knowledge Dicovery (Nifi)")
    password: SecretStr = Field(default="", description="Admin password for Knowledge Discovery (Nifi)")


class CustomizerSettingsAVTS(BaseModel):
    """Class for Aviator Search (AVTS) related settings."""

    enabled: bool = Field(default=False, description="Enable Aviator Search configuration")
    username: str = Field(default="", description="Admin username for Aviator Search")
    password: SecretStr = Field(default="", description="Admin password for Aviator Search")
    client_id: str = Field(default="", description="OTDS Client ID for Aviator Search")
    client_secret: str = Field(default="", description="OTDS Client Secret for Aviator Search")
    base_url: HttpUrl | None = Field(
        default=None,
        validate_default=True,
    )


class Settings(BaseSettings):
    """Class for all settings."""

    cust_log_file: str = Field(
        default=os.path.join(tempfile.gettempdir(), "customizing.log"),
        description="Logfile for Customizer execution",
    )

    # The following CUST artifacts are created by the main.tf in the python module:
    cust_settings_dir: str = Field(
        default="/settings/",
        description="Location where AdminSettings xml files are located",
    )
    cust_payload_dir: str = Field(default="/payload/", deprecated=True)
    cust_payload: str = Field(
        default=f"{cust_payload_dir}payload.yaml",
        description="Location of the payload file. File can be in YAML or in Terraform TFVARS Format.",
    )
    cust_payload_gz: str = Field(
        default=f"{cust_payload_dir}payload.yml.gz.b64",
        description="Location of the payload file in gz format, unzip format must bei either YAML or Terraform TFVARS.",
    )
    cust_payload_external: str = Field(default="/payload-external/", deprecated=True)

    cust_target_folder_nickname: str = Field(
        default="deployment",
        description="Nickname of folder to upload payload and log files",
    )

    cust_rm_settings_dir: str = Field(default="/settings/")
    stop_on_error: bool = Field(
        default=False,
        description="Stop the payload processing when an error during the transport package deployment occours. This can be useful for debugging, to identify missing dependencies.",
    )

    status_file_check: bool = Field(
        default=True,
        description="Check for previous exection of a payload section, set to False to force the execution",
    )

    placeholder_values: dict = Field(default={})

    profiling: bool = Field(
        default=False,
        description="Profiling can only be enabled when using the CustomizerAPI. Switch to enable python profiling using cProfile. Result is a log file with the cProfile results, as well as a dump of the profiling session. The files are located in the logdir. The files are located in the logdir. Profilig is disabled by default.",
    )

    headless_browser: bool = Field(default=True, description="Headless Browser for the BrowserAutomation")

    otds: CustomizerSettingsOTDS = CustomizerSettingsOTDS()
    otcs: CustomizerSettingsOTCS = CustomizerSettingsOTCS()
    otac: CustomizerSettingsOTAC = CustomizerSettingsOTAC()
    otpd: CustomizerSettingsOTPD = CustomizerSettingsOTPD()
    otiv: CustomizerSettingsOTIV = CustomizerSettingsOTIV()
    k8s: CustomizerSettingsK8S = CustomizerSettingsK8S()
    otawp: CustomizerSettingsOTAWP = CustomizerSettingsOTAWP()
    m365: CustomizerSettingsM365 = CustomizerSettingsM365()
    coreshare: CustomizerSettingsCoreShare = CustomizerSettingsCoreShare()
    aviator: CustomizerSettingsAviator = CustomizerSettingsAviator()
    otkd: CustomizerSettingsKnowledgeDiscovery = CustomizerSettingsKnowledgeDiscovery()
    avts: CustomizerSettingsAVTS = CustomizerSettingsAVTS()
    otmm: CustomizerSettingsOTMM = CustomizerSettingsOTMM()

    model_config = SettingsConfigDict(
        toml_file="config.toml",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    @classmethod
    def settings_customise_sources(  # noqa: D102
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,  # noqa: ARG003
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            TomlConfigSettingsSource(settings_cls),
        )

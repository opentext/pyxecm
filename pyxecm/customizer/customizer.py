"""[Automate OpenText Directory Services (OTDS) and Extended ECM (OTCS) configurations]

Data classes to handle settings read from environment variables
* CustomizerSettings: Class to manage settings
* CustomizerSettingsOTDS: Class for OTDS related settings
* CustomizerSettingsOTCS: Class for OTCS related settings
* CustomizerSettingsOTAC: Class for OTAC related settings
* CustomizerSettingsOTPD: Class for OTPD related settings
* CustomizerSettingsOTIV: Class for OTIV related settings
* CustomizerSettingsK8S: Class for K8s related settings
* CustomizerSettingsOTAWP: Class for OTAWP related settings
* CustomizerSettingsM365: Class for O365 related settings
* CustomizerSettingsAviator: Class for Aviator related settings

Methods of class Customizer:

__init__: object initializer for class Customizer
log_header: Helper method to output a section header in the log file
init_browser_automation: initialize browser automation for Content Aviator
init_m365: initialize the Microsoft 365 object
init_k8s: initialize the Kubernetes object we use to talk to the Kubernetes API
init_otds: initialize the OTDS object
init_otac: initialize the OTAC object
init_otcs: initialize the OTCS (Extended ECM) object
init_otiv: initialize the OTIV (Intelligent Viewing) object and its OTDS settings
init_otpd: initialize the PowerDocs object
init_otawp: initialize OTDS settings for AppWorks Platform

restart_otcs_service: restart the OTCS backend and frontend pods -
                      required to make certain configurations effective
restart_otac_service: restart spawner process in Archive Center
restart_otawp_pod: restart the AppWorks Platform Pod to make settings effective
consolidate_otds: consolidate OTDS users / groups (to get to a fully synchronized state)

import_powerdocs_configuration: import PowerDocs database

set_maintenance_mode: Enable or Disable Maintenance Mode

customization_run: Central function to initiate the customization

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
import uuid
import xml.etree.ElementTree as ET
import json
import re

# from packaging.version import Version

import requests

# OpenText specific modules:
import yaml
from pyxecm import OTAC, OTCS, OTDS, OTIV, OTPD, OTMM, CoreShare, OTAWP
from pyxecm.avts import AVTS
from pyxecm.customizer.k8s import K8s
from pyxecm.customizer.m365 import M365
from pyxecm.customizer.payload import Payload

from pyxecm.customizer.browser_automation import BrowserAutomation

logger = logging.getLogger("pyxecm.customizer")


@dataclass
class CustomizerSettings:
    """Class to manage settings"""

    placeholder_values: dict = field(default_factory=dict)
    stop_on_error: bool = os.environ.get("STOP_ON_ERROR", "false").lower() == "true"
    cust_log_file: str = "/tmp/customizing.log"
    customizer_start_time = customizer_end_time = datetime.now()

    # The following CUST artifacts are created by the main.tf in the python module:
    cust_settings_dir: str = "/settings/"
    cust_payload_dir: str = "/payload/"
    cust_payload: str = cust_payload_dir + "payload.yaml"
    cust_payload_gz: str = cust_payload_dir + "payload.yml.gz.b64"
    cust_payload_external: str = "/payload-external/"

    cust_target_folder_nickname: str = (
        "deployment"  # nickname of folder to upload payload and log files
    )
    # CUST_RM_SETTINGS_DIR = "/opt/opentext/cs/appData/supportasset/Settings/"
    cust_rm_settings_dir = cust_settings_dir


@dataclass
class CustomizerSettingsOTDS:
    """Class for OTDS related settings"""

    protocol: str = os.environ.get("OTDS_PROTOCOL", "http")
    public_protocol: str = os.environ.get("OTDS_PUBLIC_PROTOCOL", "https")
    hostname: str = os.environ.get("OTDS_HOSTNAME", "otds")
    port: int = os.environ.get("OTDS_SERVICE_PORT_OTDS", 80)
    username: str = os.environ.get("OTDS_ADMIN", "admin")
    otds_ticket: str | None = None
    admin_partition: str = "otds.admin"
    public_url: str = os.environ.get("OTDS_PUBLIC_URL")
    password: str = os.environ.get("OTDS_PASSWORD")
    bindPassword: str = os.environ.get("BINB_PASSWORD")
    disable_password_policy: bool = True
    enable_audit: bool = True


@dataclass
class CustomizerSettingsOTCS:
    """Class for OTCS related settings"""

    # Content Server Constants:
    protocol: str = os.environ.get("OTCS_PROTOCOL", "http")
    public_protocol: str = os.environ.get("OTCS_PUBLIC_PROTOCOL", "https")
    hostname: str = os.environ.get("OTCS_HOSTNAME", "otcs-admin-0")
    hostname_backend: str = os.environ.get("OTCS_HOSTNAME", "otcs-admin-0")
    hostname_frontend: str = os.environ.get("OTCS_HOSTNAME_FRONTEND", "otcs-frontend")
    public_url: str = os.environ.get("OTCS_PUBLIC_URL", "otcs.public-url.undefined")
    port: int = os.environ.get("OTCS_SERVICE_PORT_OTCS", 8080)
    port_backend: int = os.environ.get("OTCS_SERVICE_PORT_OTCS", 8080)
    port_frontend: int = 80
    base_path: str = "/cs/cs"
    feme_uri: str = os.environ.get("FEME_URI", "ws://feme:4242")
    admin: str = os.environ.get("OTCS_ADMIN", "admin")
    password: str = os.environ.get("OTCS_PASSWORD")
    partition: str = os.environ.get("OTCS_PARTITION", "Content Server Members")
    resource_name: str = "cs"
    k8s_statefulset_frontend: str = "otcs-frontend"
    k8s_statefulset_backend: str = "otcs-admin"
    k8s_ingress: str = "otxecm-ingress"
    maintenance_mode: bool = (
        os.environ.get("OTCS_MAINTENANCE_MODE", "true").lower() == "true"
    )
    license_feature: str = "X3"

    # K8s service name and port for maintenance pod
    maintenance_service_name: str = "otxecm-customizer"
    mainteance_service_port: int = 5555

    replicas_frontend = 0
    replicas_backend = 0

    # Add configuration options for Customizer behaviour
    update_admin_user: bool = True
    upload_config_files: bool = True
    upload_status_files: bool = True
    upload_log_file: bool = True


@dataclass
class CustomizerSettingsOTAC:
    """Class for OTAC related settings"""

    enabled: bool = os.environ.get("OTAC_ENABLED", "false").lower() == "true"
    hostname: str = os.environ.get("OTAC_SERVICE_HOST", "otac-0")
    port: int = os.environ.get("OTAC_SERVICE_PORT", 8080)
    protocol: str = os.environ.get("OTAC_PROTOCOL", "http")
    public_url: str = os.environ.get("OTAC_PUBLIC_URL")
    admin: str = os.environ.get("OTAC_ADMIN", "dsadmin")
    password: str = os.environ.get("OTAC_PASSWORD", "")
    known_server: str = os.environ.get("OTAC_KNOWN_SERVER", "")
    k8s_pod_name: str = "otac-0"


@dataclass
class CustomizerSettingsOTPD:
    """Class for OTPD related settings"""

    enabled: bool = os.environ.get("OTPD_ENABLED", "false").lower() == "true"
    hostname: str = os.environ.get("OTPD_SERVICE_HOST", "otpd")
    port: int = os.environ.get("OTPD_SERVICE_PORT", 8080)
    protocol: str = os.environ.get("OTPD_PROTOCOL", "http")
    db_importfile: str = os.environ.get(
        "OTPD_DBIMPORTFILE", "URL://url.download.location/file.zip"
    )
    tenant: str = os.environ.get("OTPD_TENANT", "Successfactors")
    user: str = os.environ.get("OTPD_USER", "powerdocsapiuser")
    password: str = os.environ.get(
        "OTPD_PASSWORD",
    )
    k8s_pod_name: str = "otpd-0"


@dataclass
class CustomizerSettingsOTIV:
    """Class for OTIV related settings"""

    enabled: bool = os.environ.get("OTIV_ENABLED", "false").lower() == "true"
    license_file: str = "/payload/otiv-license.lic"
    license_feature: str = "FULLTIME_USERS_REGULAR"
    product_name: str = "Viewing"
    product_description: str = "OpenText Intelligent Viewing"
    resource_name: str = "iv"


@dataclass
class CustomizerSettingsK8S:
    """Class for K8s related settings"""

    enabled: bool = os.environ.get("K8S_ENABLED", "true").lower() == "true"
    in_cluster: bool = True
    kubeconfig_file: str = "~/.kube/config"
    namespace: str = "default"


@dataclass
class CustomizerSettingsOTAWP:
    """Class for OTAWP related settings"""

    enabled: bool = os.environ.get("OTAWP_ENABLED", "false").lower() == "true"
    license_file: str = "/payload/otawp-license.lic"
    product_name: str = "APPWORKS_PLATFORM"
    product_description: str = "OpenText Appworks Platform"
    resource_name: str = "awp"
    access_role_name: str = "Access to " + resource_name
    admin: str = os.environ.get("OTAWP_ADMIN", "sysadmin")
    password: str = os.environ.get("OTCS_PASSWORD")
    public_protocol: str = os.environ.get("OTAWP_PROTOCOL", "https")
    public_url: str = os.environ.get("OTAWP_PUBLIC_URL")
    k8s_statefulset: str = "appworks"
    k8s_configmap: str = "appworks-config-ymls"
    port: int = os.environ.get("OTAWP_SERVICE_PORT", 8080)
    protocol: str = os.environ.get("OTPD_PROTOCOL", "http")


@dataclass
class CustomizerSettingsM365:
    """Class for O365 related settings"""

    enabled: bool = os.environ.get("O365_ENABLED", "false").lower() == "true"
    tenant_id: str = os.environ.get("O365_TENANT_ID", "")
    client_id: str = os.environ.get("O365_CLIENT_ID", "")
    client_secret: str = os.environ.get("O365_CLIENT_SECRET", "")
    user: str = os.environ.get("O365_USER", "")
    password: str = os.environ.get("O365_PASSWORD", "")
    domain: str = os.environ.get("O365_DOMAIN", "")
    sku_id: str = os.environ.get("O365_SKU_ID", "c7df2760-2c81-4ef7-b578-5b5392b571df")
    teams_app_name: str = os.environ.get("O365_TEAMS_APP_NAME", "OpenText Extended ECM")
    teams_app_external_id: str = os.environ.get(
        "O365_TEAMS_APP_ID", "dd4af790-d8ff-47a0-87ad-486318272c7a"
    )


@dataclass
class CustomizerSettingsCoreShare:
    """Class for Core Share related settings"""

    enabled: bool = os.environ.get("CORE_SHARE_ENABLED", "false").lower() == "true"
    base_url: str = os.environ.get("CORE_SHARE_BASE_URL", "https://core.opentext.com")
    sso_url: str = os.environ.get("CORE_SHARE_SSO_URL", "https://sso.core.opentext.com")
    client_id: str = os.environ.get("CORE_SHARE_CLIENT_ID", "")
    client_secret = os.environ.get("CORE_SHARE_CLIENT_SECRET", "")
    username: str = os.environ.get("CORE_SHARE_USERNAME", "")
    password: str = os.environ.get("CORE_SHARE_PASSWORD", "")


@dataclass
class CustomizerSettingsAviator:
    """Class for Aviator related settings"""

    enabled: bool = os.environ.get("AVIATOR_ENABLED", "false").lower() == "true"


@dataclass
class CustomizerSettingsAVTS:
    """Class for Aviator Search (AVTS) related settings"""

    enabled: bool = os.environ.get("AVTS_ENABLED", "false").lower() == "true"
    otds_url = os.environ.get("AVTS_OTDS_URL", "")
    client_id = os.environ.get("AVTS_CLIENT_ID", "")
    client_secret = os.environ.get("AVTS_CLIENT_SECRET", "")
    base_url = os.environ.get("AVTS_BASE_URL", "")
    username = os.environ.get("AVTS_USERNAME", "")
    password = os.environ.get("AVTS_PASSWORD", "")


class Customizer:
    """Customizer Class to control the cusomization automation

    Args: None
    """

    def __init__(
        self,
        settings: CustomizerSettings = CustomizerSettings(),
        otds: CustomizerSettingsOTDS = CustomizerSettingsOTDS(),
        otcs: CustomizerSettingsOTCS = CustomizerSettingsOTCS(),
        otac: CustomizerSettingsOTAC = CustomizerSettingsOTAC(),
        otpd: CustomizerSettingsOTPD = CustomizerSettingsOTPD(),
        otiv: CustomizerSettingsOTIV = CustomizerSettingsOTIV(),
        k8s: CustomizerSettingsK8S = CustomizerSettingsK8S(),
        otawp: CustomizerSettingsOTAWP = CustomizerSettingsOTAWP(),
        m365: CustomizerSettingsM365 = CustomizerSettingsM365(),
        core_share: CustomizerSettingsCoreShare = CustomizerSettingsCoreShare(),
        aviator: CustomizerSettingsAviator = CustomizerSettingsAviator(),
        avts: CustomizerSettingsAVTS = CustomizerSettingsAVTS(),
    ):
        self.settings = settings

        # OTDS Constants:
        self.otds_settings = otds

        # Content Server Constants:
        self.otcs_settings = otcs

        # Archive Center constants:
        self.otac_settings = otac

        # PowerDocs constants:
        self.otpd_settings = otpd

        # Intelligent Viewing constants:
        self.otiv_settings = otiv

        # AppWorks Platform constants:
        self.otawp_settings = otawp

        # K8s Mode
        self.k8s_settings = k8s

        # Microsoft 365 Environment variables:
        self.m365_settings = m365

        # Core Share Environment variables:
        self.core_share_settings = core_share

        # Aviator variables:
        self.aviator_settings = aviator

        # Aviator Search variables:
        self.avts_settings = avts

        # Initialize Objects for later assignment
        self.otds_object: OTDS | None = None
        self.otcs_object: OTCS | None = None
        self.otcs_backend_object: OTCS | None = None
        self.otcs_frontend_object: OTCS | None = None
        self.otpd_object: OTPD | None = None
        self.otac_object: OTAC | None = None
        self.otiv_object: OTIV | None = None
        self.k8s_object: K8s | None = None
        self.m365_object: M365 | None = None
        self.core_share_object: CoreShare | None = None
        self.browser_automation_object: BrowserAutomation | None = None
        self.otawp_object: OTAWP | None = None

    # end initializer

    def log_header(self, text: str, char: str = "=", length: int = 80):
        """Helper method to output a section header in the log file

        Args:
            text (str): Headline text to output into the log file.
            char (str, optional): header line character. Defaults to "=".
            length (int, optional): maxium length. Defaults to 80.
        Returns:
            None
        """

        # Calculate the remaining space for the text after adding spaces
        available_space = max(
            0, length - len(text) - 2
        )  # 2 accounts for the spaces each side of the text

        # Calculate the number of characters needed on each side
        char_count = available_space // 2
        extra_char = available_space % 2  # do we have lost 1 char?

        # Ensure there are at least 3 characters on each side
        char_count = max(3, char_count)

        # Build the header string, extra_char is either 0 or 1
        logger.info(
            "%s %s %s", char * char_count, text, char * (char_count + extra_char)
        )

    # end method definition

    def init_m365(self) -> M365:
        """Initialize the M365 object we use to talk to the Microsoft Graph API.

        Args:
            None
        Returns:
            object: M365 object or None if the object couldn't be created or
                    the authentication fails.
        """

        logger.info(
            "Microsoft 365 Tenant ID             = %s", self.m365_settings.tenant_id
        )
        logger.info(
            "Microsoft 365 Client ID             = %s", self.m365_settings.client_id
        )
        logger.debug(
            "Microsoft 365 Client Secret         = %s", self.m365_settings.client_secret
        )
        logger.info(
            "Microsoft 365 User                  = %s",
            (
                self.m365_settings.user
                if self.m365_settings.user != ""
                else "<not configured>"
            ),
        )
        logger.debug(
            "Microsoft 365 Password              = %s",
            (
                self.m365_settings.password
                if self.m365_settings.password != ""
                else "<not configured>"
            ),
        )
        logger.info(
            "Microsoft 365 Domain                = %s", self.m365_settings.domain
        )
        logger.info(
            "Microsoft 365 Default License SKU   = %s", self.m365_settings.sku_id
        )
        logger.info(
            "Microsoft 365 Teams App Name        = %s",
            self.m365_settings.teams_app_name,
        )
        logger.info(
            "Microsoft 365 Teams App External ID = %s",
            self.m365_settings.teams_app_external_id,
        )

        m365_object = M365(
            tenant_id=self.m365_settings.tenant_id,
            client_id=self.m365_settings.client_id,
            client_secret=self.m365_settings.client_secret,
            domain=self.m365_settings.domain,
            sku_id=self.m365_settings.sku_id,
            teams_app_name=self.m365_settings.teams_app_name,
            teams_app_external_id=self.m365_settings.teams_app_external_id,
        )

        if m365_object and m365_object.authenticate():
            logger.info("Connected to Microsoft Graph API.")
        else:
            logger.error("Failed to connect to Microsoft Graph API.")
            return m365_object

        logger.info(
            "Download M365 Teams App -> '%s' (external ID = %s) from Extended ECM (OTCS)...",
            self.m365_settings.teams_app_name,
            self.m365_settings.teams_app_external_id,
        )

        # Download MS Teams App from OTCS (this has with 23.2 a nasty side-effect
        # of unsetting 2 checkboxes on that config page - we reset these checkboxes
        # with the settings file "O365Settings.xml"):
        response = self.otcs_frontend_object.download_config_file(
            "/cs/cs?func=officegroups.DownloadTeamsPackage",
            "/tmp/ot.xecm.teams.zip",
        )
        # this app upload will be done with the user credentials - this is required:
        m365_object.authenticate_user(
            self.m365_settings.user, self.m365_settings.password
        )

        # Check if the app is already installed in the apps catalog
        # ideally we want to use the
        app_exist = False

        # If the App External ID is provided via Env variable then we
        # prefer to use it instead of the App name:
        if self.m365_settings.teams_app_external_id:
            logger.info(
                "Check if M365 Teams App -> '%s' (%s) is already installed in catalog using external app ID...",
                self.m365_settings.teams_app_name,
                self.m365_settings.teams_app_external_id,
            )
            response = m365_object.get_teams_apps(
                filter_expression="externalId eq '{}'".format(
                    self.m365_settings.teams_app_external_id
                )
            )
            # this should always be True as ID is unique:
            app_exist = m365_object.exist_result_item(
                response=response,
                key="externalId",
                value=self.m365_settings.teams_app_external_id,
            )
        # If the app could not be found via the external ID we fall back to
        # search for the app by name:
        if not app_exist:
            if self.m365_settings.teams_app_external_id:
                logger.info(
                    "Could not find M365 Teams App using the external ID -> %s. Try to lookup the app by name -> '%s' instead...",
                    self.m365_settings.teams_app_external_id,
                    self.m365_settings.teams_app_name,
                )
            logger.info(
                "Check if M365 Teams App -> '%s' is already installed in catalog (using app name)...",
                self.m365_settings.teams_app_name,
            )
            response = m365_object.get_teams_apps(
                filter_expression="contains(displayName, '{}')".format(
                    self.m365_settings.teams_app_name
                )
            )
            app_exist = m365_object.exist_result_item(
                response=response,
                key="displayName",
                value=self.m365_settings.teams_app_name,
            )
        if app_exist:
            # We double check that we have the effective name of the app
            # in the catalog to avoid errors when the app is looked up
            # by its wrong name in the customizer automation. This can
            # happen if the app is installed manually or the environment
            # variable is set to a wrong name.
            app_catalog_name = m365_object.get_result_value(response, "displayName")
            if app_catalog_name != self.m365_settings.teams_app_name:
                logger.warning(
                    "The Extended ECM app name -> '%s' in the M365 Teams catalog does not match the defined app name '%s'! Somebody must have manually installed the app with the wrong name!",
                    app_catalog_name,
                    self.m365_settings.teams_app_name,
                )
                # Align the name in the settings dict with the existing name in the catalog.
                self.m365_settings.teams_app_name = app_catalog_name
                # Align the name in the M365 object config dict with the existing name in the catalog.
                m365_object.config()["teamsAppName"] = app_catalog_name
            app_internal_id = m365_object.get_result_value(
                response=response, key="id", index=0
            )  # 0 = Index = first item
            # Store the internal ID for later use
            m365_object.config()["teamsAppInternalId"] = app_internal_id
            app_catalog_version = m365_object.get_result_value(
                response=response,
                key="version",
                index=0,
                sub_dict_name="appDefinitions",
            )
            logger.info(
                "M365 Teams App -> '%s' (external ID = %s) is already in app catalog with app internal ID -> %s and version -> %s. Check if we have a newer version to upload...",
                self.m365_settings.teams_app_name,
                self.m365_settings.teams_app_external_id,
                app_internal_id,
                app_catalog_version,
            )
            app_download_version = m365_object.extract_version_from_app_manifest(
                app_path="/tmp/ot.xecm.teams.zip"
            )
            if app_catalog_version < app_download_version:
                logger.info(
                    "Upgrading Extended ECM Teams App in catalog from version -> %s to version -> %s...",
                    app_catalog_version,
                    app_download_version,
                )
                response = m365_object.upload_teams_app(
                    app_path="/tmp/ot.xecm.teams.zip",
                    update_existing_app=True,
                    app_catalog_id=app_internal_id,
                )
                app_internal_id = m365_object.get_result_value(
                    response=response,
                    key="teamsAppId",
                )
                if app_internal_id:
                    logger.info(
                        "Successfully upgraded Extended ECM Teams App -> %s (external ID = %s). Internal App ID -> %s",
                        self.m365_settings.teams_app_name,
                        self.m365_settings.teams_app_external_id,
                        app_internal_id,
                    )
                    # Store the internal ID for later use
                    m365_object.config()["teamsAppInternalId"] = app_internal_id
                else:
                    logger.error(
                        "Failed to upgrade Extended ECM Teams App -> %s (external ID = %s).",
                        self.m365_settings.teams_app_name,
                        self.m365_settings.teams_app_external_id,
                    )
            else:
                logger.info(
                    "No upgrade required. The downloaded version -> %s is not newer than the version -> %s which is already in the M365 app catalog.",
                    app_download_version,
                    app_catalog_version,
                )
        else:  # Extended ECM M365 Teams app is not yet installed...
            logger.info(
                "Extended Teams ECM App -> '%s' (external ID = %s) is not yet in app catalog. Installing as new app...",
                self.m365_settings.teams_app_name,
                self.m365_settings.teams_app_external_id,
            )
            response = m365_object.upload_teams_app(
                app_path="/tmp/ot.xecm.teams.zip", update_existing_app=False
            )
            app_internal_id = m365_object.get_result_value(
                response=response,
                key="id",  # for new installs it is NOT "teamsAppId" but "id" as we use a different M365 Graph API endpoint !!!
            )
            if app_internal_id:
                logger.info(
                    "Successfully installed Extended ECM Teams App -> '%s' (external ID = %s). Internal App ID -> %s",
                    self.m365_settings.teams_app_name,
                    self.m365_settings.teams_app_external_id,
                    app_internal_id,
                )
                # Store the internal ID for later use
                m365_object.config()["teamsAppInternalId"] = app_internal_id
            else:
                logger.error(
                    "Failed to install Extended ECM Teams App -> '%s' (external ID = %s).",
                    self.m365_settings.teams_app_name,
                    self.m365_settings.teams_app_external_id,
                )

        # logger.info("======== Upload Outlook Add-In ============")

        # # Download MS Outlook Add-In from OTCS:
        # MANIFEST_FILE = "/tmp/BusinessWorkspace.Manifest.xml"
        # if not self.otcs_frontend_object.download_config_file(
        #     "/cs/cs?func=outlookaddin.DownloadManifest",
        #     MANIFEST_FILE,
        #     "DeployedContentServer",
        #     self.otcs_settings.public_url,
        # ):
        #     logger.error("Failed to download M365 Outlook Add-In from Extended ECM!")
        # else:
        #     # THIS IS NOT IMPLEMENTED DUE TO LACK OF M365 GRAPH API SUPPORT!
        #     # Do it manually for now: https://admin.microsoft.com/#/Settings/IntegratedApps
        #     logger.info("Successfully downloaded M365 Outlook Add-In from Extended ECM to %s", MANIFEST_FILE)
        #     m365_object.upload_outlook_app(MANIFEST_FILE)

        return m365_object

    # end method definition

    def init_avts(self) -> AVTS:
        """Initialize the Core Share object we use to talk to the Core Share API.

        Args:
            None
        Returns:
            object: CoreShare object or None if the object couldn't be created or
                    the authentication fails.
        """

        logger.info(
            "Aviator Search Base URL             = %s", self.avts_settings.base_url
        )
        logger.info(
            "Aviator Search OTDS URL             = %s", self.avts_settings.otds_url
        )
        logger.info(
            "Aviator Search Client ID            = %s", self.avts_settings.client_id
        )
        logger.debug(
            "Aviator Search Client Secret        = %s",
            self.avts_settings.client_secret,
        )
        logger.info(
            "Aviator Search User ID              = %s", self.avts_settings.username
        )
        logger.debug(
            "Aviator Search User Password        = %s",
            self.avts_settings.password,
        )

        avts_object = AVTS(
            otds_url=self.avts_settings.otds_url,
            base_url=self.avts_settings.base_url,
            client_id=self.avts_settings.client_id,
            client_secret=self.avts_settings.client_secret,
            username=self.avts_settings.username,
            password=self.avts_settings.password,
        )

        return avts_object

    # end method definition

    def init_coreshare(self) -> CoreShare:
        """Initialize the Core Share object we use to talk to the Core Share API.

        Args:
            None
        Returns:
            object: CoreShare object or None if the object couldn't be created or
                    the authentication fails.
        """

        logger.info(
            "Core Share Base URL             = %s", self.core_share_settings.base_url
        )
        logger.info(
            "Core Share SSO URL              = %s", self.core_share_settings.sso_url
        )
        logger.info(
            "Core Share Client ID            = %s", self.core_share_settings.client_id
        )
        logger.debug(
            "Core Share Client Secret        = %s",
            self.core_share_settings.client_secret,
        )
        logger.info(
            "Core Share User                 = %s",
            (
                self.core_share_settings.username
                if self.core_share_settings.username != ""
                else "<not configured>"
            ),
        )
        logger.debug(
            "Core Share Password             = %s",
            (
                self.core_share_settings.password
                if self.core_share_settings.password != ""
                else "<not configured>"
            ),
        )

        core_share_object = CoreShare(
            base_url=self.core_share_settings.base_url,
            sso_url=self.core_share_settings.sso_url,
            client_id=self.core_share_settings.client_id,
            client_secret=self.core_share_settings.client_secret,
            username=self.core_share_settings.username,
            password=self.core_share_settings.password,
        )

        if core_share_object and core_share_object.authenticate_admin():
            logger.info("Connected to Core Share as Tenant Admin.")
        else:
            logger.error("Failed to connect to Core Share as Tenant Admin.")

        if core_share_object and core_share_object.authenticate_user():
            logger.info("Connected to Core Share as Tenant Service User.")
        else:
            logger.error("Failed to connect to Core Share as Tenant Service User.")

        return core_share_object

    # end method definition

    def init_k8s(self) -> K8s:
        """Initialize the Kubernetes object we use to talk to the Kubernetes API.

        Args:
            None
        Returns:
            K8s: K8s object
        Side effects:
            The global variables otcs_replicas_frontend and otcs_replicas_backend are initialized
        """

        logger.info("Connection parameters Kubernetes (K8s):")
        logger.info("K8s inCluster       = %s", self.k8s_settings.in_cluster)
        logger.info("K8s namespace       = %s", self.k8s_settings.namespace)
        logger.info(
            "K8s kubeconfig file = %s",
            self.k8s_settings.kubeconfig_file,
        )

        k8s_object = K8s(
            in_cluster=self.k8s_settings.in_cluster,
            kubeconfig_file=self.k8s_settings.kubeconfig_file,
            namespace=self.k8s_settings.namespace,
        )
        if k8s_object:
            logger.info("Kubernetes API is ready now.")
        else:
            logger.error("Cannot establish connection to Kubernetes.")

        # Get number of replicas for frontend:
        otcs_frontend_scale = k8s_object.get_stateful_set_scale(
            self.otcs_settings.k8s_statefulset_frontend
        )
        if not otcs_frontend_scale:
            logger.error(
                "Cannot find Kubernetes Stateful Set -> '%s' for OTCS Frontends!",
                self.otcs_settings.k8s_statefulset_frontend,
            )
            sys.exit()

        self.otcs_settings.replicas_frontend = otcs_frontend_scale.spec.replicas  # type: ignore
        logger.info(
            "Stateful Set -> '%s' has -> %s replicas",
            self.otcs_settings.k8s_statefulset_frontend,
            self.otcs_settings.replicas_frontend,
        )

        # Get number of replicas for backend:
        otcs_backend_scale = k8s_object.get_stateful_set_scale(
            self.otcs_settings.k8s_statefulset_backend
        )
        if not otcs_backend_scale:
            logger.error(
                "Cannot find Kubernetes Stateful Set -> '%s' for OTCS Backends!",
                self.otcs_settings.k8s_statefulset_backend,
            )
            sys.exit()

        self.otcs_settings.replicas_backend = otcs_backend_scale.spec.replicas  # type: ignore
        logger.info(
            "Stateful Set -> '%s' has -> %s replicas",
            self.otcs_settings.k8s_statefulset_backend,
            self.otcs_settings.replicas_backend,
        )

        return k8s_object

    # end method definition

    def init_otds(self) -> OTDS:
        """Initialize the OTDS object and parameters and authenticate at OTDS once it is ready.

        Args:
            None
        Returns:
            object: OTDS object
        """

        logger.info("Connection parameters OTDS:")
        logger.info("OTDS Protocol          = %s", self.otds_settings.protocol)
        logger.info("OTDS Public Protocol   = %s", self.otds_settings.public_protocol)
        logger.info("OTDS Hostname          = %s", self.otds_settings.hostname)
        logger.info("OTDS Public URL        = %s", self.otds_settings.public_url)
        logger.info("OTDS Port              = %s", str(self.otds_settings.port))
        logger.info("OTDS Admin User        = %s", self.otds_settings.username)
        logger.debug("OTDS Admin Password    = %s", self.otds_settings.password)
        logger.debug("OTDS Ticket            = %s", self.otds_settings.otds_ticket)
        logger.info("OTDS Admin Partition   = %s", self.otds_settings.admin_partition)

        otds_object = OTDS(
            protocol=self.otds_settings.protocol,
            hostname=self.otds_settings.hostname,
            port=self.otds_settings.port,
            username=self.otds_settings.username,
            password=self.otds_settings.password,
            otds_ticket=self.otds_settings.otds_ticket,
            bindPassword=self.otds_settings.bindPassword
        )

        logger.info("Authenticating to OTDS...")
        otds_cookie = otds_object.authenticate()
        while otds_cookie is None:
            logger.warning("Waiting 30 seconds for OTDS to become ready...")
            time.sleep(30)
            otds_cookie = otds_object.authenticate()
        logger.info("OTDS is ready now.")

        logger.info("Enable OTDS audit...")

        if self.otds_settings.enable_audit:
            otds_object.enable_audit()

        if self.otds_settings.disable_password_policy:
            logger.info("Disable OTDS password expiry...")
            # Setting the value to 0 disables password expiry.
            # The default is 90 days and we may have Terrarium
            # instances that are running longer than that. This
            # avoids problems with customerizer re-runs of
            # instances that are > 90 days old.
            otds_object.update_password_policy(
                update_values={"passwordMaximumDuration": 0}
            )

        return otds_object

    # end method definition

    def init_otac(self) -> OTAC:
        """Initialize the OTAC object and parameters.
          Configure the Archive Server as a known server
          if environment variable OTAC_KNOWN_SERVER is set.

        Args: None
        Return:
            OTAC object
        """

        logger.info("Connection parameters OTAC:")
        logger.info("OTAC Protocol          = %s", self.otac_settings.protocol)
        logger.info("OTAC Hostname          = %s", self.otac_settings.hostname)
        logger.info("OTAC Public URL        = %s", self.otac_settings.public_url)
        logger.info("OTAC Port              = %s", str(self.otac_settings.port))
        logger.info("OTAC Admin User        = %s", self.otac_settings.admin)
        logger.debug("OTAC Admin Password   = %s", self.otac_settings.password)
        logger.info(
            "OTAC Known Server      = %s",
            (
                self.otac_settings.known_server
                if self.otac_settings.known_server != ""
                else "<not configured>"
            ),
        )

        otac_object = OTAC(
            self.otac_settings.protocol,
            self.otac_settings.hostname,
            int(self.otac_settings.port),
            self.otac_settings.admin,
            self.otac_settings.password,
            self.otds_settings.username,
            self.otds_settings.password,
        )

        # This is a work-around as OTCS container automation is not
        # enabling the certificate reliable.
        response = otac_object.enable_certificate(
            cert_name="SP_otcs-admin-0", cert_type="ARC"
        )
        if not response:
            logger.error("Failed to enable OTAC certificate for Extended ECM!")
        else:
            logger.info("Successfully enabled OTAC certificate for Extended ECM!")

        # is there a known server configured for Archive Center (to sync content with)
        if otac_object and self.otac_settings.known_server != "":
            # wait until the OTAC pod is in ready state
            logger.info("Waiting for Archive Center to become ready...")
            self.k8s_object.wait_pod_condition(self.otac_settings.k8s_pod_name, "Ready")

            logger.info("Configure known host for Archive Center...")
            response = otac_object.exec_command(
                f"cf_create_host {self.otac_settings.known_server} 0 /archive 8080 8090"
            )
            if not response or not response.ok:
                logger.error("Failed to configure known host for Archive Center!")

            logger.info("Configure host alias for Archive Center...")
            response = otac_object.exec_command(
                f"cf_set_variable MY_HOST_ALIASES {self.otac_settings.k8s_pod_name},{self.otac_settings.public_url},otac DS"
            )
            if not response or not response.ok:
                logger.error("Failed to configure host alias for Archive Center!")

            # Restart the spawner in Archive Center:
            logger.info("Restart Archive Center Spawner...")
            self.restart_otac_service()
        else:
            logger.info(
                "Skip configuration of known host for Archive Center (OTAC_KNOWN_SERVER is not set)."
            )

        return otac_object

    # end method definition

    def init_otcs(
        self,
        hostname: str,
        port: int,
        partition_name: str,
        resource_name: str,
    ) -> OTCS:
        """Initialize the OTCS class and parameters and authenticate at OTCS once it is ready.

        Args:
            hostname (str): OTCS hostname
            port (int): port number of OTCS
            partition_name (str): name of OTDS Partition for Extended ECM users
            resource_name (str): name of OTDS resource for Extended ECM
        Returns:
            OTCS: OTCS object
        """

        logger.info("Connection parameters OTCS (Extended ECM):")
        logger.info("OTCS Protocol              = %s", self.otcs_settings.protocol)
        logger.info(
            "OTCS Public Protocol       = %s", self.otcs_settings.public_protocol
        )
        logger.info("OTCS Hostname              = %s", hostname)
        logger.info("OTCS Public URL            = %s", self.otcs_settings.public_url)
        logger.info("OTCS Port                  = %s", str(port))
        logger.info("OTCS Admin User            = %s", self.otcs_settings.admin)
        logger.debug("OTCS Admin Password        = %s", self.otcs_settings.password)
        logger.info("OTCS User Partition        = %s", partition_name)
        logger.info("OTCS Resource Name         = %s", resource_name)
        logger.info(
            "OTCS User Default License  = %s", self.otcs_settings.license_feature
        )
        logger.info(
            "OTCS K8s Frontend Pods     = %s",
            self.otcs_settings.k8s_statefulset_frontend,
        )
        logger.info(
            "OTCS K8s Backend Pods      = %s",
            self.otcs_settings.k8s_statefulset_backend,
        )
        logger.info(
            "FEME URI                   = %s",
            self.otcs_settings.feme_uri,
        )

        logger.debug("Checking if OTCS object has already been initialized")

        otds_ticket = (
            self.otds_object.cookie()["OTDSTicket"] if self.otds_object else None
        )
        otcs_object = OTCS(
            self.otcs_settings.protocol,
            hostname,
            int(port),
            self.otcs_settings.public_protocol + "://" + self.otcs_settings.public_url,
            self.otcs_settings.admin,
            self.otcs_settings.password,
            partition_name,
            resource_name,
            otds_ticket=otds_ticket,
            base_path=self.otcs_settings.base_path,
            feme_uri=self.otcs_settings.feme_uri,
        )

        # It is important to wait for OTCS to be configured - otherwise we
        # may interfere with the OTCS container automation and run into errors
        logger.info("Wait for OTCS to be configured...")
        otcs_configured = otcs_object.is_configured()
        while not otcs_configured:
            logger.warning("OTCS is not configured yet. Waiting 30 seconds...")
            time.sleep(30)
            otcs_configured = otcs_object.is_configured()
        logger.info("OTCS is configured now.")

        logger.info("Authenticating to OTCS...")
        otcs_cookie = otcs_object.authenticate()
        while otcs_cookie is None:
            logger.warning("Waiting 30 seconds for OTCS to become ready...")
            time.sleep(30)
            otcs_cookie = otcs_object.authenticate()
        logger.info("OTCS is ready now.")

        #        if self.otcs_settings.update_admin_user:
        # Set first name and last name of Admin user (ID = 1000):
        #            otcs_object.update_user(1000, field="first_name", value="Terrarium")
        #            otcs_object.update_user(1000, field="last_name", value="Admin")

        if "OTCS_RESSOURCE_ID" not in self.settings.placeholder_values:
            self.settings.placeholder_values["OTCS_RESSOURCE_ID"] = (
                self.otds_object.get_resource(self.otcs_settings.resource_name)[
                    "resourceID"
                ]
            )
            logger.debug(
                "Placeholder values after OTCS init = %s",
                self.settings.placeholder_values,
            )

        if self.otawp_settings.enabled:
            otcs_resource = self.otds_object.get_resource(
                self.otcs_settings.resource_name
            )
            otcs_resource["logoutURL"] = (
                f"{self.otawp_settings.public_protocol}://{self.otawp_settings.public_url}/home/system/wcp/sso/sso_logout.htm"
            )
            otcs_resource["logoutMethod"] = "GET"

            self.otds_object.update_resource(name="cs", resource=otcs_resource)

        # Allow impersonation of the resource for all users:
        self.otds_object.impersonate_resource(resource_name)

        return otcs_object

    # end method definition

    def init_otiv(self) -> OTIV | None:
        """Initialize the OTIV (Intelligent Viewing) object and its OTDS settings.

        Args:
        Returns:
            objects: OTIV object
        """

        logger.info("Parameters for OTIV (Intelligent Viewing):")
        logger.info("OTDS Resource Name       = %s", self.otiv_settings.resource_name)
        logger.info("OTIV License File        = %s", self.otiv_settings.license_file)
        logger.info("OTIV Product Name        = %s", self.otiv_settings.product_name)
        logger.info(
            "OTIV Product Description = %s", self.otiv_settings.product_description
        )
        logger.info("OTIV License Feature     = %s", self.otiv_settings.license_feature)

        otiv_object = OTIV(
            resource_name=self.otiv_settings.resource_name,
            product_name=self.otiv_settings.product_name,
            product_description=self.otiv_settings.product_description,
            license_file=self.otiv_settings.license_file,
            default_license=self.otiv_settings.license_feature,
        )

        otiv_resource = self.otds_object.get_resource(self.otiv_settings.resource_name)
        while otiv_resource is None:
            logger.warning(
                "OTDS Resource -> %s for Intelligent Viewing not found. OTIV may not be ready. Wait 30 sec...",
                self.otiv_settings.resource_name,
            )
            time.sleep(30)
            otiv_resource = self.otds_object.get_resource(
                self.otiv_settings.resource_name
            )

        otiv_license = self.otds_object.add_license_to_resource(
            self.otiv_settings.license_file,
            self.otiv_settings.product_name,
            self.otiv_settings.product_description,
            otiv_resource["resourceID"],
        )
        if not otiv_license:
            logger.info(
                "Couldn't apply license -> %s for product -> %s. Intelligent Viewing may not be deployed!",
                self.otiv_settings.license_file,
                self.otiv_settings.product_name,
            )
            return None

        # Workaround for VAT-4580 (24.2.0)
        update_publisher = self.otds_object.update_user(
            partition="Content Server Service Users",
            user_id="iv-publisher",
            attribute_name="oTType",
            attribute_value="ServiceUser",
        )
        while update_publisher is None:
            update_publisher = self.otds_object.update_user(
                partition="Content Server Service Users",
                user_id="iv-publisher",
                attribute_name="oTType",
                attribute_value="ServiceUser",
            )
            time.sleep(30)

        logger.info("OTDS user iv-publisher -> updating oTType=ServiceUser")

        return otiv_object

    # end method definition

    def init_otpd(self) -> OTPD:
        """Initialize the OTPD (PowerDocs) object and parameters.

        Args:
            None
        Returns:
            object: OTPD (PowerDocs) object
        """

        logger.info("Connection parameters OTPD (PowerDocs):")
        logger.info("OTPD Protocol             = %s", self.otpd_settings.protocol)
        logger.info("OTPD Hostname             = %s", self.otpd_settings.hostname)
        logger.info("OTPD Port                 = %s", str(self.otpd_settings.port))
        logger.info("OTPD API User             = %s", self.otpd_settings.user)
        logger.info("OTPD Tenant               = %s", self.otpd_settings.tenant)
        logger.info(
            "OTPD Database Import File = %s",
            (
                self.otpd_settings.db_importfile
                if self.otpd_settings.db_importfile != ""
                else "<not configured>"
            ),
        )
        logger.info("OTPD K8s Pod Name         = %s", self.otpd_settings.k8s_pod_name)

        otpd_object = OTPD(
            self.otpd_settings.protocol,
            self.otpd_settings.hostname,
            int(self.otpd_settings.port),
            self.otpd_settings.user,
            self.otpd_settings.password,
        )

        # wait until the OTPD pod is in ready state
        self.k8s_object.wait_pod_condition(self.otpd_settings.k8s_pod_name, "Ready")

        # We have a race condition here. Even if the pod is ready
        # it may not yet have fully initialized its database.
        # Then the "apply_setting()" calls below may fail with
        # an error. This should be improved in the future. For now
        # we just wait a minute hoping that the DB is initialized then.
        logger.info("Wait some time for PowerDocs database to be initialized...")
        time.sleep(60)
        logger.info("Configure some basic PowerDocs settings...")

        # Fix settings for local Kubernetes deployments.
        # Unclear why this is not the default.
        if otpd_object:
            otpd_object.apply_setting("LocalOtdsUrl", "http://otds/otdsws")
            otpd_object.apply_setting(
                "LocalApplicationServerUrlForContentManager",
                "http://localhost:8080/c4ApplicationServer",
                self.otpd_settings.tenant,
            )

        return otpd_object

        # end function definition

    def init_otawp(self):
        """Initialize OTDS for Appworks Platform
        Args:
        Return: None
        """

        logger.info("Connection parameters OTAWP:")
        logger.info("OTAWP Enabled          = %s", str(self.otawp_settings.enabled))
        logger.info("OTAWP Resource         = %s", self.otawp_settings.resource_name)
        logger.info("OTAWP Access Role      = %s", self.otawp_settings.access_role_name)
        logger.info("OTAWP Admin User       = %s", self.otawp_settings.admin)
        logger.debug("OTAWP Password         = %s", self.otawp_settings.password)
        logger.info("OTAWP K8s Stateful Set = %s", self.otawp_settings.k8s_statefulset)
        logger.info("OTAWP K8s Config Map   = %s", self.otawp_settings.k8s_configmap)

        logger.info(
            "Wait for OTCS to create its OTDS resource with name -> '%s'...",
            self.otcs_settings.resource_name,
        )

        # Loop to wait for OTCS to create its OTDS resource
        # (we need it to update the AppWorks K8s Config Map):
        otcs_resource = self.otds_object.get_resource(self.otcs_settings.resource_name)
        while otcs_resource is None:
            logger.warning(
                "OTDS resource for Content Server with name -> '%s' does not exist yet. Waiting...",
                self.otcs_settings.resource_name,
            )
            time.sleep(30)
            otcs_resource = self.otds_object.get_resource(
                self.otcs_settings.resource_name
            )

        otcs_resource_id = otcs_resource["resourceID"]

        logger.info("OTDS resource ID for Content Server -> %s", otcs_resource_id)

        # make sure code is idempotent and only try to add ressource if it doesn't exist already:
        awp_resource = self.otds_object.get_resource(self.otawp_settings.resource_name)
        if not awp_resource:
            logger.info(
                "OTDS resource -> '%s' for AppWorks Platform does not yet exist. Creating...",
                self.otawp_settings.resource_name,
            )
            # Create a Python dict with the special payload we need for AppWorks:
            additional_payload = {}
            additional_payload["connectorid"] = "rest"
            additional_payload["resourceType"] = "rest"
            user_attribute_mapping = [
                {
                    "sourceAttr": ["oTExternalID1"],
                    "destAttr": "__NAME__",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["displayname"],
                    "destAttr": "DisplayName",
                    "mappingFormat": "%s",
                },
                {"sourceAttr": ["mail"], "destAttr": "Email", "mappingFormat": "%s"},
                {
                    "sourceAttr": ["oTTelephoneNumber"],
                    "destAttr": "Telephone",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTMobile"],
                    "destAttr": "Mobile",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTFacsimileTelephoneNumber"],
                    "destAttr": "Fax",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTStreetAddress,l,st,postalCode,c"],
                    "destAttr": "Address",
                    "mappingFormat": "%s%n%s %s %s%n%s",
                },
                {
                    "sourceAttr": ["oTCompany"],
                    "destAttr": "Company",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["ds-pwp-account-disabled"],
                    "destAttr": "AccountDisabled",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTExtraAttr9"],
                    "destAttr": "IsServiceAccount",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["custom:proxyConfiguration"],
                    "destAttr": "ProxyConfiguration",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["c"],
                    "destAttr": "Identity-CountryOrRegion",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["gender"],
                    "destAttr": "Identity-Gender",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["displayName"],
                    "destAttr": "Identity-DisplayName",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTStreetAddress"],
                    "destAttr": "Identity-Address",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["l"],
                    "destAttr": "Identity-City",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["mail"],
                    "destAttr": "Identity-Email",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["givenName"],
                    "destAttr": "Identity-FirstName",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["sn"],
                    "destAttr": "Identity-LastName",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["initials"],
                    "destAttr": "Identity-MiddleNames",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTMobile"],
                    "destAttr": "Identity-Mobile",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["postalCode"],
                    "destAttr": "Identity-PostalCode",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["st"],
                    "destAttr": "Identity-StateOrProvince",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["title"],
                    "destAttr": "Identity-title",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["physicalDeliveryOfficeName"],
                    "destAttr": "Identity-physicalDeliveryOfficeName",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTFacsimileTelephoneNumber"],
                    "destAttr": "Identity-oTFacsimileTelephoneNumber",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["notes"],
                    "destAttr": "Identity-notes",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTCompany"],
                    "destAttr": "Identity-oTCompany",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTDepartment"],
                    "destAttr": "Identity-oTDepartment",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["birthDate"],
                    "destAttr": "Identity-Birthday",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["cn"],
                    "destAttr": "Identity-UserName",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["Description"],
                    "destAttr": "Identity-UserDescription",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["oTTelephoneNumber"],
                    "destAttr": "Identity-Phone",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["displayName"],
                    "destAttr": "Identity-IdentityDisplayName",
                    "mappingFormat": "%s",
                },
            ]
            additional_payload["userAttributeMapping"] = user_attribute_mapping
            group_attribute_mapping = [
                {
                    "sourceAttr": ["cn"],
                    "destAttr": "__NAME__",
                    "mappingFormat": '%js:function format(name) { return name.replace(/&/g,"-and-"); }',
                },
                {
                    "sourceAttr": ["description"],
                    "destAttr": "Description",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["description"],
                    "destAttr": "Identity-Description",
                    "mappingFormat": "%s",
                },
                {
                    "sourceAttr": ["displayName"],
                    "destAttr": "Identity-DisplayName",
                    "mappingFormat": "%s",
                },
            ]
            additional_payload["groupAttributeMapping"] = group_attribute_mapping
            additional_payload["connectorName"] = "REST (Generic)"
            additional_payload["pcCreatePermissionAllowed"] = "true"
            additional_payload["pcModifyPermissionAllowed"] = "true"
            additional_payload["pcDeletePermissionAllowed"] = "false"
            additional_payload["connectionParamInfo"] = [
                {
                    "name": "fBaseURL",
                    "value": "http://appworks:8080/home/system/app/otdspush",
                },
                {"name": "fUsername", "value": self.otawp_settings.admin},
                {"name": "fPassword", "value": self.otawp_settings.password},
            ]

            awp_resource = self.otds_object.add_resource(
                name=self.otawp_settings.resource_name,
                description="AppWorks Platform",
                display_name="AppWorks Platform",
                additional_payload=additional_payload,
            )
        else:
            logger.info(
                "OTDS resource -> %s for AppWorks Platform does already exist.",
                self.otawp_settings.resource_name,
            )

        awp_resource_id = awp_resource["resourceID"]

        logger.info("OTDS resource ID for AppWorks Platform -> %s", awp_resource_id)

        self.settings.placeholder_values["OTAWP_RESOURCE_ID"] = str(awp_resource_id)

        logger.debug(
            "Placeholder values after OTAWP init = %s", self.settings.placeholder_values
        )

        logger.info("Update AppWorks Kubernetes Config Map with OTDS resource IDs...")

        config_map = self.k8s_object.get_config_map(self.otawp_settings.k8s_configmap)
        if not config_map:
            logger.error(
                "Failed to retrieve AppWorks Kubernetes Config Map -> %s",
                self.otawp_settings.k8s_configmap,
            )
        else:
            solution = yaml.safe_load(config_map.data["solution.yaml"])  # type: ignore

            # Change values as required
            solution["platform"]["organizations"]["system"]["otds"][
                "resourceId"
            ] = awp_resource_id
            solution["platform"]["content"]["ContentServer"][
                "contentServerUrl"
            ] = f"{self.otcs_settings.public_protocol}://{self.otcs_settings.public_url}/cs/cs"
            solution["platform"]["content"]["ContentServer"][
                "contentServerSupportDirectoryUrl"
            ] = f"{self.otcs_settings.public_protocol}://{self.otcs_settings.public_url}/cssupport"
            solution["platform"]["content"]["ContentServer"][
                "otdsResourceId"
            ] = otcs_resource_id
            solution["platform"]["authenticators"]["OTDS_auth"]["publicLoginUrl"] = (
                self.otds_settings.public_protocol
                + "://"
                + self.otds_settings.public_url
                + "/otdsws/login"
            )
            solution["platform"]["security"]["contentSecurityPolicy"] = (
                "frame-ancestors 'self' "
                + self.otcs_settings.public_protocol
                + "://"
                + self.otcs_settings.public_url
            )
            data = {"solution.yaml": yaml.dump(solution)}
            result = self.k8s_object.replace_config_map(
                self.otawp_settings.k8s_configmap, data
            )
            if result:
                logger.info("Successfully updated AppWorks Solution YAML.")
            else:
                logger.error("Failed to update AppWorks Solution YAML.")
            logger.debug("Solution YAML for AppWorks -> %s", solution)

        logger.info("Scale AppWorks Kubernetes Stateful Set to 1...")
        self.k8s_object.scale_stateful_set(
            sts_name=self.otawp_settings.k8s_statefulset, scale=1
        )

        # Add the OTCS Admin user to the AppWorks Access Role in OTDS
        self.otds_object.add_user_to_access_role(
            "Access to " + self.otawp_settings.resource_name, "otadmin@otds.admin"
        )

        # Loop to wait for OTCS to create its OTDS user partition:
        otcs_partition = self.otds_object.get_partition(
            self.otcs_settings.partition, show_error=False
        )
        while otcs_partition is None:
            logger.warning(
                "OTDS user partition for Content Server with name -> '%s' does not exist yet. Waiting...",
                self.otcs_settings.partition,
            )

            time.sleep(30)
            otcs_partition = self.otds_object.get_partition(
                self.otcs_settings.partition, show_error=False
            )

        # Add the OTDS user partition for OTCS to the AppWorks Platform Access Role in OTDS.
        # This will effectvely sync all OTCS users with AppWorks Platform:
        self.otds_object.add_partition_to_access_role(
            self.otawp_settings.access_role_name, self.otcs_settings.partition
        )

        # Add the OTDS admin partition to the AppWorks Platform Access Role in OTDS.
        self.otds_object.add_partition_to_access_role(
            self.otawp_settings.access_role_name, self.otds_settings.admin_partition
        )

        # Set Group inclusion for Access Role for OTAWP to "True":
        self.otds_object.update_access_role_attributes(
            self.otawp_settings.access_role_name,
            [{"name": "pushAllGroups", "values": ["True"]}],
        )

        # Add ResourceID User to OTDSAdmin to allow push
        self.otds_object.add_user_to_group(
            user=str(awp_resource_id) + "@otds.admin", group="otdsadmins@otds.admin"
        )

        # Allow impersonation for all users:
        self.otds_object.impersonate_resource(self.otawp_settings.resource_name)

        # Add SPS license for OTAWP
        # check if the license file exists, otherwise skip for versions pre 24.1
        if os.path.isfile(self.otawp_settings.license_file):
            logger.info(
                "Found OTAWP license file -> '%s', assiging it to ressource '%s'...",
                self.otawp_settings.license_file,
                self.otawp_settings.resource_name,
            )

            otawp_license = self.otds_object.add_license_to_resource(
                self.otawp_settings.license_file,
                self.otawp_settings.product_name,
                self.otawp_settings.product_description,
                awp_resource["resourceID"],
            )
            if not otawp_license:
                logger.error(
                    "Couldn't apply license -> '%s' for product -> '%s' to OTDS resource -> '%s'",
                    self.otawp_settings.license_file,
                    self.otawp_settings.product_name,
                    awp_resource["resourceID"],
                )
            else:
                logger.info(
                    "Successfully applied license -> '%s' for product -> '%s' to OTDS resource -> '%s'",
                    self.otawp_settings.license_file,
                    self.otawp_settings.product_name,
                    awp_resource["resourceID"],
                )

            # Assign AppWorks license to Content Server Members Partiton and otds.admin:
            for partition_name in ["otds.admin", self.otcs_settings.partition]:
                if self.otds_object.is_partition_licensed(
                    partition_name=partition_name,
                    resource_id=awp_resource["resourceID"],
                    license_feature="USERS",
                    license_name=self.otawp_settings.product_name,
                ):
                    logger.info(
                        "Partition -> %s is already licensed for -> %s (%s)",
                        partition_name,
                        self.otawp_settings.product_name,
                        "USERS",
                    )
                else:
                    assigned_license = self.otds_object.assign_partition_to_license(
                        partition_name,
                        awp_resource["resourceID"],
                        "USERS",
                        self.otawp_settings.product_name,
                    )
                    if not assigned_license:
                        logger.error(
                            "Partition -> '%s' could not be assigned to license -> '%s' (%s)",
                            partition_name,
                            self.otawp_settings.product_name,
                            "USERS",
                        )
                    else:
                        logger.info(
                            "Partition -> '%s' successfully assigned to license -> '%s' (%s)",
                            partition_name,
                            self.otawp_settings.product_name,
                            "USERS",
                        )
        otawp_object = OTAWP(
            self.otawp_settings.protocol,
            self.otawp_settings.k8s_statefulset,
            str(self.otawp_settings.port),
            "sysadmin",
            self.otawp_settings.password,
            "",
        )
        return otawp_object

    # end method definition

    def restart_otcs_service(self, otcs_object: OTCS, extra_wait_time: int = 60):
        """Restart the Content Server service in all OTCS pods

        Args:
            otcs_object: OTCS class instance (object)
        Returns:
            None
        """

        if not self.k8s_object:
            logger.warning(
                "Kubernetes integration not available, skipping restart of services"
            )
            return

        logger.info("Restart OTCS frontend and backend pods...")

        # Restart all frontends:
        for x in range(0, self.otcs_settings.replicas_frontend):
            pod_name = self.otcs_settings.k8s_statefulset_frontend + "-" + str(x)

            logger.info("Deactivate Liveness probe for pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "touch /tmp/keepalive"],
                container="otcs-frontend-container",
            )
            logger.info("Restarting pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "/opt/opentext/cs/stop_csserver"],
                container="otcs-frontend-container",
            )
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "/opt/opentext/cs/start_csserver"],
                container="otcs-frontend-container",
            )

        # Restart all backends:
        for x in range(0, self.otcs_settings.replicas_backend):
            pod_name = self.otcs_settings.k8s_statefulset_backend + "-" + str(x)

            logger.info("Deactivate Liveness probe for pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "touch /tmp/keepalive"],
                container="otcs-admin-container",
            )
            logger.info("Restarting pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "/opt/opentext/cs/stop_csserver"],
                container="otcs-admin-container",
            )
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "/opt/opentext/cs/start_csserver"],
                container="otcs-admin-container",
            )

        logger.info("Re-Authenticating to OTCS after restart of pods...")
        otcs_cookie = otcs_object.authenticate(revalidate=True)
        while otcs_cookie is None:
            logger.warning("Waiting 30 seconds for OTCS to become ready...")
            time.sleep(30)
            otcs_cookie = otcs_object.authenticate(revalidate=True)
        logger.info("OTCS is ready again.")

        # Reactivate Liveness probes in all pods:
        for x in range(0, self.otcs_settings.replicas_frontend):
            pod_name = self.otcs_settings.k8s_statefulset_frontend + "-" + str(x)

            logger.info("Reactivate Liveness probe for pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "rm /tmp/keepalive"],
                container="otcs-frontend-container",
            )

        for x in range(0, self.otcs_settings.replicas_backend):
            pod_name = self.otcs_settings.k8s_statefulset_backend + "-" + str(x)

            logger.info("Reactivate Liveness probe for pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "rm /tmp/keepalive"],
                container="otcs-admin-container",
            )

        logger.info("Restart OTCS frontend and backend pods has been completed.")

        # optional, give some additional time to make sure service is responsive
        if extra_wait_time > 0:
            logger.info(
                "Wait %s seconds to make sure OTCS is responsive again...",
                str(extra_wait_time),
            )
            time.sleep(extra_wait_time)
        logger.info("Continue customizing...")

    # end method definition

    def restart_otac_service(self) -> bool:
        """Restart the Archive Center spawner service in OTAC pod

        Args:
            None
        Returns:
            bool: True if restart was done, False if error occured
        """

        if not self.otac_settings.enabled:
            return False

        logger.info(
            "Restarting spawner service in Archive Center pod -> '%s'",
            self.otac_settings.k8s_pod_name,
        )
        # The Archive Center Spawner needs to be run in "interactive" mode - otherwise the command will "hang":
        # The "-c" parameter is not required in this case
        # False is given as parameter as OTAC writes non-errors to stderr
        response = self.k8s_object.exec_pod_command_interactive(
            self.otac_settings.k8s_pod_name,
            ["/bin/sh", "/etc/init.d/spawner restart"],
            60,
            False,
        )

        if response:
            return True
        else:
            return False

    # end method definition

    def restart_otawp_pod(self):
        """Delete the AppWorks Platform Pod to make Kubernetes restart it.

        Args:
        Returns:
            None
        """

        self.k8s_object.delete_pod(self.otawp_settings.k8s_statefulset + "-0")

    # end method definition

    def consolidate_otds(self):
        """Consolidate OTDS resources
        Args:
        Return: None
        """

        self.otds_object.consolidate(self.otcs_settings.resource_name)

        if self.otawp_settings.enabled:  # is AppWorks Platform deployed?
            self.otds_object.consolidate(self.otawp_settings.resource_name)

    # end method definition

    def import_powerdocs_configuration(self, otpd_object: OTPD):
        """Import a database export (zip file) into the PowerDocs database

        Args:
            otpd_object (object): PowerDocs object
        """

        if self.otpd_settings.db_importfile.startswith("http"):
            # Download file from remote location specified by the OTPD_DBIMPORTFILE
            # this must be a public place without authentication:
            logger.info(
                "Download PowerDocs database file from URL -> '%s'",
                self.otpd_settings.db_importfile,
            )

            try:
                package = requests.get(self.otpd_settings.db_importfile, timeout=60)
                package.raise_for_status()
                logger.info(
                    "Successfully downloaded PowerDocs database file -> '%s'; status code -> %s",
                    self.otpd_settings.db_importfile,
                    package.status_code,
                )
                filename = "/tmp/otpd_db_import.zip"
                with open(filename, mode="wb") as localfile:
                    localfile.write(package.content)

                logger.info(
                    "Starting import on %s://%s:%s of %s",
                    self.otpd_settings.protocol,
                    self.otpd_settings.hostname,
                    self.otpd_settings.port,
                    self.otpd_settings.db_importfile,
                )
                response = otpd_object.import_database(filename=filename)
                logger.info("Response -> %s", response)

            except requests.exceptions.HTTPError as err:
                logger.error("Request error -> %s", err)

    # end method definition

    def set_maintenance_mode(self, enable: bool = True):
        """Enable or Disable Maintenance Mode

        Args:
            enable (bool, optional): _description_. Defaults to True.
        """
        if enable and self.k8s_settings.enabled:
            self.log_header("Enable Maintenance Mode")
            logger.info(
                "Put OTCS frontends in Maitenance Mode by changing the Kubernetes Ingress backend service..."
            )
            self.k8s_object.update_ingress_backend_services(
                self.otcs_settings.k8s_ingress,
                "otcs",
                self.otcs_settings.maintenance_service_name,
                self.otcs_settings.mainteance_service_port,
            )
            logger.info("OTCS frontend is now in Maintenance Mode!")
        elif not self.k8s_settings.enabled:
            logger.warning(
                "Kubernetes Integration disabled - Cannot Enable/Disable Maintenance Mode"
            )
            self.k8s_object = None
        else:
            # Changing the Ingress backend service to OTCS frontend service:
            logger.info(
                "Put OTCS frontend back in Production Mode by changing the Kubernetes Ingress backend service..."
            )
            self.k8s_object.update_ingress_backend_services(
                self.otcs_settings.k8s_ingress,
                "otcs",
                self.otcs_settings.hostname_frontend,
                self.otcs_settings.port_frontend,
            )
            logger.info("OTCS frontend is now back in Production Mode!")

    # end method definition

    def customization_run(self):
        """Central function to initiate the customization"""
        # Set Timer for duration calculation
        self.settings.customizer_start_time = self.settings.customizer_end_time = (
            datetime.now()
        )

        # Initialize the OTDS, OTCS and OTPD objects and wait for the
        # pods to be ready. If any of this fails we bail out:

        self.log_header("Initialize OTDS")

        self.otds_object = self.init_otds()
        if not self.otds_object:
            logger.error("Failed to initialize OTDS - exiting...")
            sys.exit()

        # Establish in-cluster Kubernetes connection
        self.log_header("Initialize Kubernetes")
        if self.k8s_settings.enabled:
            self.k8s_object = self.init_k8s()

            if not self.k8s_object:
                logger.error("Failed to initialize Kubernetes - exiting...")
                sys.exit()

        # Put Frontend in Maintenance mode to make sure nobody interferes
        # during customization:
        if self.otcs_settings.maintenance_mode:
            self.set_maintenance_mode(True)

        if self.otawp_settings.enabled:  # is AppWorks Platform deployed?
            self.log_header("Initialize OTAWP")

            # Configure required OTDS resources as AppWorks doesn't do this on its own:
            self.otawp_object = self.init_otawp()
        else:
            self.settings.placeholder_values["OTAWP_RESOURCE_ID"] = ""

        self.log_header("Initialize OTCS backend")
        self.otcs_backend_object = self.init_otcs(
            self.otcs_settings.hostname_backend,
            int(self.otcs_settings.port_backend),
            self.otcs_settings.partition,
            self.otcs_settings.resource_name,
        )
        if not self.otcs_backend_object:
            logger.error("Failed to initialize OTCS backend - exiting...")
            sys.exit()

        self.log_header("Initialize OTCS frontend")
        self.otcs_frontend_object = self.init_otcs(
            self.otcs_settings.hostname_frontend,
            int(self.otcs_settings.port_frontend),
            self.otcs_settings.partition,
            self.otcs_settings.resource_name,
        )
        if not self.otcs_frontend_object:
            logger.error("Failed to initialize OTCS frontend - exiting...")
            sys.exit()

        if self.otac_settings.enabled:  # is Archive Center deployed?
            self.log_header("Initialize OTAC")

            self.otac_object = self.init_otac()
            if not self.otac_object:
                logger.error("Failed to initialize OTAC - exiting...")
                sys.exit()
        else:
            self.otac_object = None

        if self.otiv_settings.enabled:  # is Intelligent Viewing deployed?
            self.log_header("Initialize OTIV")

            self.otiv_object = self.init_otiv()
        else:
            self.otiv_object = None

        if self.otpd_settings.enabled:  # is PowerDocs deployed?
            self.log_header("Initialize OTPD")

            self.otpd_object = self.init_otpd()
            if not self.otpd_object:
                logger.error("Failed to initialize OTPD - exiting...")
                sys.exit()
        else:
            self.otpd_object = None

        if self.core_share_settings.enabled:  # is Core Share enabled?
            self.log_header("Initialize Core Share")

            self.core_share_object = self.init_coreshare()
            if not self.core_share_object:
                logger.error("Failed to initialize Core Share - exiting...")
                sys.exit()
        else:
            self.core_share_object = None

        if (
            self.m365_settings.enabled
            and self.m365_settings.user != ""
            and self.m365_settings.password != ""
        ):  # is M365 enabled?
            self.log_header("Initialize Microsoft 365")

            # Initialize the M365 object and connection to M365 Graph API:
            self.m365_object = self.init_m365()
            if not self.m365_object:
                logger.error("Failed to initialize Microsoft 365!")
                sys.exit()

        if self.avts_settings.enabled:
            self.log_header("Initialize Aviator Search")
            self.avts_object = self.init_avts()
            if not self.avts_object:
                logger.error("Failed to initialize Aviator Search")
                sys.exit()
        else:
            self.avts_object = None

        self.log_header("Processing Payload")

        cust_payload_list = []
        # Is uncompressed payload provided?
        if os.path.exists(self.settings.cust_payload):
            logger.info("Found payload file -> '%s'", self.settings.cust_payload)
            cust_payload_list.append(self.settings.cust_payload)
        # Is compressed payload provided?
        if os.path.exists(self.settings.cust_payload_gz):
            logger.info(
                "Found compressed payload file -> '%s'", self.settings.cust_payload_gz
            )
            cust_payload_list.append(self.settings.cust_payload_gz)

        # do we have additional payload as an external file?
        if os.path.exists(self.settings.cust_payload_external):
            for filename in sorted(
                os.scandir(self.settings.cust_payload_external), key=lambda e: e.name
            ):
                if filename.is_file() and os.path.getsize(filename) > 0:
                    logger.info("Found external payload file -> '%s'", filename.path)
                    cust_payload_list.append(filename.path)
        else:
            logger.info(
                "No external payload file -> '%s'", self.settings.cust_payload_external
            )

        for cust_payload in cust_payload_list:
            # Open the payload file. If this fails we bail out:
            logger.info("Starting processing of payload -> '%s'", cust_payload)

            # Set startTime for duration calculation
            start_time = datetime.now()

            payload_object = Payload(
                payload_source=cust_payload,
                custom_settings_dir=self.settings.cust_settings_dir,
                k8s_object=self.k8s_object,
                otds_object=self.otds_object,
                otac_object=self.otac_object,
                otcs_backend_object=self.otcs_backend_object,
                otcs_frontend_object=self.otcs_frontend_object,
                otcs_restart_callback=self.restart_otcs_service,
                otiv_object=self.otiv_object,
                m365_object=self.m365_object,
                core_share_object=self.core_share_object,
                browser_automation_object=self.browser_automation_object,
                placeholder_values=self.settings.placeholder_values,  # this dict includes placeholder replacements for the Ressource IDs of OTAWP and OTCS
                log_header_callback=self.log_header,
                stop_on_error=self.settings.stop_on_error,
                aviator_enabled=self.aviator_settings.enabled,
                upload_status_files=self.otcs_settings.upload_status_files,
                otawp_object=self.otawp_object,
                avts_object=self.avts_object,
            )
            # Load the payload file and initialize the payload sections:
            if not payload_object.init_payload():
                logger.error(
                    "Failed to initialize payload -> %s - skipping...", cust_payload
                )
                continue

            # Now process the payload in the defined ordering:
            payload_object.process_payload()

            self.log_header("Consolidate OTDS Resources")
            self.consolidate_otds()

            # Upload payload file for later review to Enterprise Workspace
            if self.otcs_settings.upload_config_files:
                self.log_header("Upload Payload file to Extended ECM")
                response = self.otcs_backend_object.get_node_from_nickname(
                    self.settings.cust_target_folder_nickname
                )
                target_folder_id = self.otcs_backend_object.get_result_value(
                    response, "id"
                )
                if not target_folder_id:
                    target_folder_id = 2000  # use Enterprise Workspace as fallback
                # Write YAML file with upadated payload (including IDs, etc.).
                # We need to write to /tmp as initial location is read-only:
                payload_file = os.path.basename(cust_payload)
                payload_file = (
                    payload_file[: -len(".gz.b64")]
                    if payload_file.endswith(".gz.b64")
                    else payload_file
                )
                cust_payload = "/tmp/" + payload_file

                with open(cust_payload, "w", encoding="utf-8") as file:
                    yaml.dump(payload_object.get_payload(), file)

                # Check if the payload file has been uploaded before.
                # This can happen if we re-run the python container.
                # In this case we add a version to the existing document:
                response = self.otcs_backend_object.get_node_by_parent_and_name(
                    int(target_folder_id), os.path.basename(cust_payload)
                )
                target_document_id = self.otcs_backend_object.get_result_value(
                    response, "id"
                )
                if target_document_id:
                    response = self.otcs_backend_object.add_document_version(
                        int(target_document_id),
                        cust_payload,
                        os.path.basename(cust_payload),
                        "text/plain",
                        "Updated payload file after re-run of customization",
                    )
                else:
                    response = self.otcs_backend_object.upload_file_to_parent(
                        cust_payload,
                        os.path.basename(cust_payload),
                        "text/plain",
                        int(target_folder_id),
                    )

            duration = datetime.now() - start_time
            self.log_header(
                "Customizer completed processing of payload -> {} in {}".format(
                    cust_payload,
                    duration,
                )
            )

        if self.otcs_settings.maintenance_mode:
            self.set_maintenance_mode(False)

        # Restart AppWorksPlatform pod if it is deployed (to make settings effective):
        if self.otawp_settings.enabled:  # is AppWorks Platform deployed?
            otawp_resource = self.otds_object.get_resource(
                self.otawp_settings.resource_name
            )
            if (
                not "allowImpersonation" in otawp_resource
                or not otawp_resource["allowImpersonation"]
            ):
                # Allow impersonation for all users:
                logger.warning(
                    "OTAWP impersonation is not correct in OTDS before OTAWP pod restart!"
                )
            else:
                logger.info(
                    "OTAWP impersonation is correct in OTDS before OTAWP pod restart!"
                )
            logger.info("Restart OTAWP pod...")
            self.restart_otawp_pod()
            # For some reason we need to double-check that the impersonation for OTAWP has been set correctly
            # and if not set it again:
            otawp_resource = self.otds_object.get_resource(
                self.otawp_settings.resource_name
            )
            if (
                not "allowImpersonation" in otawp_resource
                or not otawp_resource["allowImpersonation"]
            ):
                # Allow impersonation for all users:
                logger.warning(
                    "OTAWP impersonation is not correct in OTDS - set it once more..."
                )
                self.otds_object.impersonate_resource(self.otawp_settings.resource_name)

        # Upload log file for later review to "Deployment" folder in "Administration" folder
        if (
            os.path.exists(self.settings.cust_log_file)
            and self.otcs_settings.upload_log_file
        ):
            self.log_header("Upload log file to Extended ECM")
            response = self.otcs_backend_object.get_node_from_nickname(
                self.settings.cust_target_folder_nickname
            )
            target_folder_id = self.otcs_backend_object.get_result_value(response, "id")
            if not target_folder_id:
                target_folder_id = 2000  # use Enterprise Workspace as fallback
            # Check if the log file has been uploaded before.
            # This can happen if we re-run the python container:
            # In this case we add a version to the existing document:
            response = self.otcs_backend_object.get_node_by_parent_and_name(
                int(target_folder_id), os.path.basename(self.settings.cust_log_file)
            )
            target_document_id = self.otcs_backend_object.get_result_value(
                response, "id"
            )
            if target_document_id:
                response = self.otcs_backend_object.add_document_version(
                    node_id=int(target_document_id),
                    file_url=self.settings.cust_log_file,
                    file_name=os.path.basename(self.settings.cust_log_file),
                    mime_type="text/plain",
                    description="Updated Python Log after re-run of customization",
                )
            else:
                response = self.otcs_backend_object.upload_file_to_parent(
                    file_url=self.settings.cust_log_file,
                    file_name=os.path.basename(self.settings.cust_log_file),
                    mime_type="text/plain",
                    parent_id=int(target_folder_id),
                    description="Initial Python Log after first run of customization",
                )

        self.settings.customizer_end_time = datetime.now()
        self.log_header(
            "Customizer completed in {}".format(
                self.settings.customizer_end_time - self.settings.customizer_start_time
            )
        )


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%d-%b-%Y %H:%M:%S",
        level=logging.INFO,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )

    my_customizer = Customizer(
        otcs=CustomizerSettingsOTCS(
            hostname="otcs.local.xecm.cloud",
            hostname_backend="otcs-admin-0",
            hostname_frontend="otcs-frontend",
            protocol="http",
            port_backend=8080,
        ),
        otds=CustomizerSettingsOTDS(hostname="otds"),
        otpd=CustomizerSettingsOTPD(enabled=False),
        otac=CustomizerSettingsOTAC(enabled=False),
        k8s=CustomizerSettingsK8S(enabled=True),
        otiv=CustomizerSettingsOTIV(enabled=False),
    )

    my_customizer.customization_run()

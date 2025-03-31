"""Module to automate Directory Services (OTDS) and Content Server (OTCS) configurations."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import requests

# OpenText specific modules:
import yaml
from pydantic import HttpUrl

from pyxecm import AVTS, OTAC, OTAWP, OTCS, OTDS, OTIV, OTPD, CoreShare
from pyxecm.customizer.k8s import K8s
from pyxecm.customizer.m365 import M365
from pyxecm.customizer.payload import Payload
from pyxecm.customizer.settings import Settings

if TYPE_CHECKING:
    from pyxecm.customizer.browser_automation import BrowserAutomation

default_logger = logging.getLogger("pyxecm.customizer")


class Customizer:
    """Customizer Class to control the cusomization automation."""

    logger: logging.Logger = default_logger
    customizer_start_time: datetime | None
    customizer_stop_time: datetime | None

    def __init__(
        self,
        settings: dict | None = None,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize Customzer object.

        Args:
            settings (dict | None, optional):
                Customizer settings. Defaults to None.
            logger (logging.Logger, optional):
                The loggoing object to be used for all log messages.
                Defaults to default_logger.

        """

        self.logger = logger

        # Create Settings class, raise ValidationError if settings are invalid
        self.settings = Settings(**settings) if settings is not None else Settings()

        # Initialize Objects:
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
        self.avts_object: AVTS | None = None

    # end initializer

    def log_header(self, text: str, char: str = "=", length: int = 120) -> None:
        """Output a section header in the log file.

        Args:
            text (str):
                Headline text to output into the log file.
            char (str, optional):
                The header line character. Defaults to "=".
            length (int, optional):
                The maximum line length. Defaults to 120.

        Returns:
            None

        """

        # Calculate the remaining space for the text after adding spaces
        available_space = max(
            0,
            length - len(text) - 2,
        )  # 2 accounts for the spaces each side of the text

        # Calculate the number of characters needed on each side
        char_count = available_space // 2
        extra_char = available_space % 2  # do we have lost 1 char?

        # Ensure there are at least 3 characters on each side
        char_count = max(3, char_count)

        # Build the header string, extra_char is either 0 or 1
        self.logger.info(
            "%s %s %s",
            char * char_count,
            text,
            char * (char_count + extra_char),
        )

    # end method definition

    def init_m365(self) -> M365:
        """Initialize the M365 object we use to talk to the Microsoft Graph API.

        Args:
            None

        Returns:
            M365 object:
                M365 object or None if the object couldn't be created or
                the authentication fails.

        """

        self.logger.info(
            "Microsoft 365 Tenant ID             = %s",
            self.settings.m365.tenant_id,
        )
        self.logger.debug(
            "Microsoft 365 Client ID             = %s",
            self.settings.m365.client_id,
        )
        self.logger.debug(
            "Microsoft 365 Client Secret         = %s",
            self.settings.m365.client_secret,
        )
        self.logger.info(
            "Microsoft 365 Domain                = %s",
            self.settings.m365.domain,
        )
        self.logger.info(
            "Microsoft 365 Default License SKU   = %s",
            self.settings.m365.sku_id,
        )
        self.logger.info(
            "Microsoft 365 Teams App Name        = %s",
            self.settings.m365.teams_app_name,
        )
        self.logger.info(
            "Microsoft 365 Teams App External ID = %s",
            self.settings.m365.teams_app_external_id,
        )
        self.logger.info(
            "Microsoft 365 SharePoint App Root Site = %s",
            self.settings.m365.sharepoint_app_root_site,
        )
        self.logger.info(
            "Microsoft 365 SharePoint App Client ID = %s",
            self.settings.m365.sharepoint_app_client_id,
        )
        self.logger.debug(
            "Microsoft 365 SharePoint App Client Secret = %s",
            self.settings.m365.sharepoint_app_client_secret,
        )

        m365_object = M365(
            tenant_id=self.settings.m365.tenant_id,
            client_id=self.settings.m365.client_id,
            client_secret=self.settings.m365.client_secret,
            domain=self.settings.m365.domain,
            sku_id=self.settings.m365.sku_id,
            teams_app_name=self.settings.m365.teams_app_name,
            teams_app_external_id=self.settings.m365.teams_app_external_id,
            sharepoint_app_root_site=self.settings.m365.sharepoint_app_root_site,
            sharepoint_app_client_id=self.settings.m365.sharepoint_app_client_id,
            sharepoint_app_client_secret=self.settings.m365.sharepoint_app_client_secret,
            logger=self.logger,
        )

        if m365_object and m365_object.authenticate():
            self.logger.info("Connected to Microsoft Graph API.")
        else:
            self.logger.error("Failed to connect to Microsoft Graph API.")
            return m365_object

        # Check if the Teams App should be updated, we don't do this always due to the bug described below
        if self.settings.m365.update_teams_app:
            self.logger.info(
                "Download M365 Teams App -> '%s' (external ID = %s) from Extended ECM (OTCS)...",
                self.settings.m365.teams_app_name,
                self.settings.m365.teams_app_external_id,
            )

            # Download MS Teams App from OTCS (this has with 23.2 a nasty side-effect
            # of unsetting 2 checkboxes on that config page - we reset these checkboxes
            # with the settings file "O365Settings.xml"):
            file_path = os.path.join(tempfile.gettempdir(), "ot.xecm.teams.zip")
            response = self.otcs_frontend_object.download_config_file(
                otcs_url_suffix="/cs/cs?func=officegroups.DownloadTeamsPackage",
                file_path=file_path,
            )

            # Check if the app is already installed in the apps catalog
            # ideally we want to use the
            app_exist = False

            # If the App External ID is provided via Env variable then we
            # prefer to use it instead of the App name:
            if self.settings.m365.teams_app_external_id:
                self.logger.info(
                    "Check if M365 Teams App -> '%s' (%s) is already installed in catalog using external app ID...",
                    self.settings.m365.teams_app_name,
                    self.settings.m365.teams_app_external_id,
                )
                response = m365_object.get_teams_apps(
                    filter_expression="externalId eq '{}'".format(
                        self.settings.m365.teams_app_external_id,
                    ),
                )
                # this should always be True as ID is unique:
                app_exist = m365_object.exist_result_item(
                    response=response,
                    key="externalId",
                    value=self.settings.m365.teams_app_external_id,
                )
            # If the app could not be found via the external ID we fall back to
            # search for the app by name:
            if not app_exist:
                if self.settings.m365.teams_app_external_id:
                    self.logger.info(
                        "Could not find M365 Teams App by external ID -> %s. Try to lookup the app by name -> '%s' instead...",
                        self.settings.m365.teams_app_external_id,
                        self.settings.m365.teams_app_name,
                    )
                self.logger.info(
                    "Check if M365 Teams App -> '%s' is already installed in catalog (using app name)...",
                    self.settings.m365.teams_app_name,
                )
                response = m365_object.get_teams_apps(
                    filter_expression="contains(displayName, '{}')".format(
                        self.settings.m365.teams_app_name,
                    ),
                )
                app_exist = m365_object.exist_result_item(
                    response=response,
                    key="displayName",
                    value=self.settings.m365.teams_app_name,
                )
            if app_exist:
                # We double check that we have the effective name of the app
                # in the catalog to avoid errors when the app is looked up
                # by its wrong name in the customizer automation. This can
                # happen if the app is installed manually or the environment
                # variable is set to a wrong name.
                app_catalog_name = m365_object.get_result_value(response, "displayName")
                if app_catalog_name != self.settings.m365.teams_app_name:
                    self.logger.warning(
                        "The Extended ECM app name -> '%s' in the M365 Teams catalog does not match the defined app name -> '%s'!",
                        app_catalog_name,
                        self.settings.m365.teams_app_name,
                    )
                    # Align the name in the settings dict with the existing name in the catalog.
                    self.settings.m365.teams_app_name = app_catalog_name
                    # Align the name in the M365 object config dict with the existing name in the catalog.
                    m365_object.config()["teamsAppName"] = app_catalog_name
                app_internal_id = m365_object.get_result_value(
                    response=response,
                    key="id",
                    index=0,
                )  # 0 = Index = first item
                # Store the internal ID for later use
                m365_object.config()["teamsAppInternalId"] = app_internal_id
                app_catalog_version = m365_object.get_result_value(
                    response=response,
                    key="version",
                    index=0,
                    sub_dict_name="appDefinitions",
                )
                self.logger.info(
                    "M365 Teams App -> '%s' (external ID = %s) is already in app catalog with app internal ID -> %s and version -> %s. Check if we have a newer version to upload...",
                    self.settings.m365.teams_app_name,
                    self.settings.m365.teams_app_external_id,
                    app_internal_id,
                    app_catalog_version,
                )
                app_path = os.path.join(tempfile.gettempdir(), "ot.xecm.teams.zip")
                app_download_version = m365_object.extract_version_from_app_manifest(
                    app_path=app_path,
                )
                if app_catalog_version < app_download_version:
                    self.logger.info(
                        "Upgrading Extended ECM Teams App in catalog from version -> %s to version -> %s...",
                        app_catalog_version,
                        app_download_version,
                    )
                    app_path = os.path.join(tempfile.gettempdir(), "ot.xecm.teams.zip")
                    response = m365_object.upload_teams_app(
                        app_path=app_path,
                        update_existing_app=True,
                        app_catalog_id=app_internal_id,
                    )
                    app_internal_id = m365_object.get_result_value(
                        response=response,
                        key="teamsAppId",
                    )
                    if app_internal_id:
                        self.logger.info(
                            "Successfully upgraded Extended ECM Teams App -> '%s' (external ID = %s). Internal App ID -> %s",
                            self.settings.m365.teams_app_name,
                            self.settings.m365.teams_app_external_id,
                            app_internal_id,
                        )
                        # Store the internal ID for later use
                        m365_object.config()["teamsAppInternalId"] = app_internal_id
                    else:
                        self.logger.error(
                            "Failed to upgrade Extended ECM Teams App -> '%s' (external ID = %s).",
                            self.settings.m365.teams_app_name,
                            self.settings.m365.teams_app_external_id,
                        )
                else:
                    self.logger.info(
                        "No upgrade required. The downloaded version -> %s is not newer than the version -> %s which is already in the M365 app catalog.",
                        app_download_version,
                        app_catalog_version,
                    )
            else:  # Extended ECM M365 Teams app is not yet installed...
                self.logger.info(
                    "Extended Teams ECM App -> '%s' (external ID = %s) is not yet in app catalog. Installing as new app...",
                    self.settings.m365.teams_app_name,
                    self.settings.m365.teams_app_external_id,
                )
                app_path = os.path.join(tempfile.gettempdir(), "ot.xecm.teams.zip")
                response = m365_object.upload_teams_app(
                    app_path=app_path,
                    update_existing_app=False,
                )
                app_internal_id = m365_object.get_result_value(
                    response=response,
                    key="id",  # for new installs it is NOT "teamsAppId" but "id" as we use a different M365 Graph API endpoint !!!
                )
                if app_internal_id:
                    self.logger.info(
                        "Successfully installed Extended ECM Teams App -> '%s' (external ID = %s). Internal App ID -> %s",
                        self.settings.m365.teams_app_name,
                        self.settings.m365.teams_app_external_id,
                        app_internal_id,
                    )
                    # Store the internal ID for later use
                    m365_object.config()["teamsAppInternalId"] = app_internal_id
                else:
                    self.logger.error(
                        "Failed to install Extended ECM Teams App -> '%s' (external ID = %s).",
                        self.settings.m365.teams_app_name,
                        self.settings.m365.teams_app_external_id,
                    )

        # self.logger.info("======== Upload Outlook Add-In ============")

        # # Download MS Outlook Add-In from OTCS:
        # MANIFEST_FILE = "/tmp/BusinessWorkspace.Manifest.xml"
        # if not self.otcs_frontend_object.download_config_file(
        #     "/cs/cs?func=outlookaddin.DownloadManifest",
        #     MANIFEST_FILE,
        #     "DeployedContentServer",
        #     self.settings.otcs.public_url,
        # ):
        #     self.logger.error("Failed to download M365 Outlook Add-In from Extended ECM!")
        # else:
        #     # THIS IS NOT IMPLEMENTED DUE TO LACK OF M365 GRAPH API SUPPORT!
        #     # Do it manually for now: https://admin.microsoft.com/#/Settings/IntegratedApps
        #     self.logger.info("Successfully downloaded M365 Outlook Add-In from Extended ECM to %s", MANIFEST_FILE)
        #     m365_object.upload_outlook_app(MANIFEST_FILE)

        return m365_object

    # end method definition

    def init_avts(self) -> AVTS:
        """Initialize the Core Share object we use to talk to the Core Share API.

        Args:
            None

        Returns:
            AVTS object:
                Aviator Search object or None if the object couldn't be created or
                the authentication fails.

        """

        self.logger.info(
            "Aviator Search Base URL             = %s",
            self.settings.avts.base_url,
        )
        self.logger.info(
            "Aviator Search OTDS URL             = %s",
            self.settings.avts.otds_url,
        )
        self.logger.info(
            "Aviator Search Client ID            = %s",
            self.settings.avts.client_id,
        )
        self.logger.debug(
            "Aviator Search Client Secret        = %s",
            self.settings.avts.client_secret,
        )
        self.logger.info(
            "Aviator Search User ID              = %s",
            self.settings.avts.username,
        )
        self.logger.debug(
            "Aviator Search User Password        = %s",
            self.settings.avts.password,
        )

        return AVTS(
            otds_url=str(self.settings.avts.otds_url),
            base_url=str(self.settings.avts.base_url),
            client_id=self.settings.avts.client_id,
            client_secret=self.settings.avts.client_secret,
            username=self.settings.avts.username,
            password=self.settings.avts.password,
            logger=self.logger,
        )

    # end method definition

    def init_coreshare(self) -> CoreShare:
        """Initialize the Core Share object we use to talk to the Core Share API.

        Args:
            None
        Returns:
            CoreShare object:
                Core Share object or None if the object couldn't be created or
                the authentication fails.

        """

        self.logger.info(
            "Core Share Base URL             = %s",
            self.settings.coreshare.base_url,
        )
        self.logger.info(
            "Core Share SSO URL              = %s",
            self.settings.coreshare.sso_url,
        )
        self.logger.info(
            "Core Share Client ID            = %s",
            self.settings.coreshare.client_id,
        )
        self.logger.debug(
            "Core Share Client Secret        = %s",
            self.settings.coreshare.client_secret,
        )
        self.logger.info(
            "Core Share User                 = %s",
            (self.settings.coreshare.username if self.settings.coreshare.username != "" else "<not configured>"),
        )
        self.logger.debug(
            "Core Share Password             = %s",
            (self.settings.coreshare.password if self.settings.coreshare.password != "" else "<not configured>"),
        )

        core_share_object = CoreShare(
            base_url=self.settings.coreshare.base_url,
            sso_url=self.settings.coreshare.sso_url,
            client_id=self.settings.coreshare.client_id,
            client_secret=self.settings.coreshare.client_secret,
            username=self.settings.coreshare.username,
            password=self.settings.coreshare.password.get_secret_value(),
            logger=self.logger,
        )

        if core_share_object and core_share_object.authenticate_admin():
            self.logger.info("Connected to Core Share as Tenant Admin.")
        else:
            self.logger.error("Failed to connect to Core Share as Tenant Admin.")

        if core_share_object and core_share_object.authenticate_user():
            self.logger.info("Connected to Core Share as Tenant Service User.")
        else:
            self.logger.error("Failed to connect to Core Share as Tenant Service User.")

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

        self.logger.info("Connection parameters Kubernetes (K8s):")
        self.logger.info("K8s namespace       = %s", self.settings.k8s.namespace)
        self.logger.info(
            "K8s kubeconfig file = %s",
            self.settings.k8s.kubeconfig_file,
        )

        k8s_object = K8s(
            kubeconfig_file=self.settings.k8s.kubeconfig_file,
            namespace=self.settings.k8s.namespace,
            logger=self.logger,
        )
        if k8s_object:
            self.logger.info("Kubernetes API is ready now.")
        else:
            self.logger.error("Cannot establish connection to Kubernetes.")

        # Get number of replicas for frontend:
        otcs_frontend_scale = k8s_object.get_stateful_set_scale(
            sts_name=self.settings.k8s.sts_otcs_frontend,
        )
        if not otcs_frontend_scale:
            self.logger.error(
                "Cannot find Kubernetes Stateful Set -> '%s' for OTCS Frontends!",
                self.settings.k8s.sts_otcs_frontend,
            )
            sys.exit()

        self.settings.k8s.sts_otcs_frontend_replicas = otcs_frontend_scale.spec.replicas
        self.logger.info(
            "Stateful Set -> '%s' has -> %s replicas",
            self.settings.k8s.sts_otcs_frontend,
            self.settings.k8s.sts_otcs_frontend_replicas,
        )

        # Get number of replicas for backend:
        otcs_backend_scale = k8s_object.get_stateful_set_scale(
            sts_name=self.settings.k8s.sts_otcs_admin,
        )
        if not otcs_backend_scale:
            self.logger.error(
                "Cannot find Kubernetes Stateful Set -> '%s' for OTCS Backends!",
                self.settings.k8s.sts_otcs_admin,
            )
            sys.exit()

        self.settings.k8s.sts_otcs_admin_replicas = otcs_backend_scale.spec.replicas
        self.logger.info(
            "Stateful Set -> '%s' has -> %s replicas",
            self.settings.k8s.sts_otcs_admin,
            self.settings.k8s.sts_otcs_admin_replicas,
        )

        return k8s_object

    # end method definition

    def init_otds(self) -> OTDS:
        """Initialize the OTDS object and parameters and authenticate at OTDS once it is ready.

        Args:
            None

        Returns:
            OTDS:
                The OTDS object

        """

        self.logger.info("Connection parameters OTDS:")
        self.logger.info("OTDS Protocol          = %s", self.settings.otds.url.scheme)
        self.logger.info(
            "OTDS Hostname          = %s",
            self.settings.otds.url_internal.host,
        )
        self.logger.info(
            "OTDS Port              = %s",
            str(self.settings.otds.url.port),
        )
        self.logger.info("OTDS Public Protocol   = %s", self.settings.otds.url.scheme)
        self.logger.info("OTDS Public URL        = %s", self.settings.otds.url.host)
        self.logger.info("OTDS Public Port       = %s", self.settings.otds.url.port)
        self.logger.info("OTDS Admin User        = %s", self.settings.otds.username)
        self.logger.debug("OTDS Admin Password   = %s", self.settings.otds.password)
        self.logger.debug("OTDS Ticket           = %s", self.settings.otds.ticket)
        self.logger.info(
            "OTDS Admin Partition   = %s",
            self.settings.otds.admin_partition,
        )

        otds_object = OTDS(
            protocol=self.settings.otds.url_internal.scheme,
            hostname=self.settings.otds.url_internal.host,
            port=self.settings.otds.url_internal.port,
            username=self.settings.otds.username,
            password=self.settings.otds.password.get_secret_value(),
            otds_ticket=self.settings.otds.ticket,
            bind_password=self.settings.otds.bind_password.get_secret_value(),
            logger=self.logger,
        )

        self.logger.info("Authenticating to OTDS...")
        otds_cookie = otds_object.authenticate()
        while otds_cookie is None:
            self.logger.info("Waiting 30 seconds for OTDS to become ready...")
            time.sleep(30)
            otds_cookie = otds_object.authenticate()
        self.logger.info("OTDS is ready now.")

        self.logger.info("Enable OTDS audit...")

        if self.settings.otds.enable_audit:
            otds_object.enable_audit()

        if self.settings.otds.disable_password_policy:
            self.logger.info("Disable OTDS password expiry...")
            # Setting the value to 0 disables password expiry.
            # The default is 90 days and we may have Terrarium
            # instances that are running longer than that. This
            # avoids problems with customerizer re-runs of
            # instances that are > 90 days old.
            otds_object.update_password_policy(
                update_values={"passwordMaximumDuration": 0},
            )

        return otds_object

    # end method definition

    def init_otac(self) -> OTAC:
        """Initialize the OTAC object and parameters.

        Configure the Archive Server as a known server
        if environment variable OTAC_KNOWN_SERVER is set.

        Args: None

        Returns:
            The OTAC object.

        """

        self.logger.info("Connection parameters OTAC:")
        self.logger.info("OTAC URL          = %s", str(self.settings.otac.url))
        self.logger.info("OTAC URL internal = %s", str(self.settings.otac.url_internal))
        self.logger.info("OTAC Admin User        = %s", self.settings.otac.username)
        self.logger.debug("OTAC Admin Password   = %s", self.settings.otac.password)
        self.logger.info(
            "OTAC Known Server      = %s",
            (self.settings.otac.known_server if self.settings.otac.known_server != "" else "<not configured>"),
        )

        otac_object = OTAC(
            self.settings.otac.url_internal.scheme,
            self.settings.otac.url_internal.host,
            int(self.settings.otac.url_internal.port),
            self.settings.otac.username,
            self.settings.otac.password.get_secret_value(),
            self.settings.otds.username,
            self.settings.otds.password.get_secret_value(),
            logger=self.logger,
        )

        self.logger.info("Authenticating to OTAC...")
        otac_cookie = otac_object.authenticate()
        while otac_cookie is None:
            self.logger.info("Waiting 30 seconds for OTAC to become ready...")
            time.sleep(30)
            otac_cookie = otac_object.authenticate()
        self.logger.info("OTAC is ready now.")

        # This is a work-around as OTCS container automation is not
        # enabling the certificate reliable.
        response = otac_object.enable_certificate(
            cert_name="SP_otcs-admin-0",
            cert_type="ARC",
        )
        if not response:
            self.logger.error("Failed to enable OTAC certificate for Extended ECM!")
        else:
            self.logger.info("Successfully enabled OTAC certificate for Extended ECM!")

        # is there a known server configured for Archive Center (to sync content with)
        if otac_object and self.settings.otac.known_server != "":
            # wait until the OTAC pod is in ready state
            self.logger.info("Waiting for Archive Center to become ready...")
            self.k8s_object.wait_pod_condition(self.settings.k8s.pod_otac, "Ready")

            self.logger.info("Configure known host for Archive Center...")
            response = otac_object.exec_command(
                f"cf_create_host {self.settings.otac.known_server} 0 /archive 8080 8090",
            )
            if not response or not response.ok:
                self.logger.error("Failed to configure known host for Archive Center!")

            self.logger.info("Configure host alias for Archive Center...")
            response = otac_object.exec_command(
                f"cf_set_variable MY_HOST_ALIASES {self.settings.k8s.pod_otac},{self.settings.otac.url.host},otac DS",
            )
            if not response or not response.ok:
                self.logger.error("Failed to configure host alias for Archive Center!")

            # Restart the spawner in Archive Center:
            self.logger.info("Restart Archive Center Spawner...")
            self.restart_otac_service()
        else:
            self.logger.info(
                "Skip configuration of known host for Archive Center (OTAC_KNOWN_SERVER is not set).",
            )

        return otac_object

    # end method definition

    def init_otcs(
        self,
        url: HttpUrl,
    ) -> OTCS:
        """Initialize the OTCS class and parameters and authenticate at OTCS once it is ready.

        Args:
            url (HttpURL):
                The OTCS URL.

        Returns:
            OTCS:
                The OTCS object

        """

        self.logger.info("Connection parameters OTCS (Extended ECM):")
        self.logger.info("OTCS URL                   = %s", str(self.settings.otcs.url))
        self.logger.info(
            "OTCS Frontend URL          = %s",
            str(self.settings.otcs.url_frontend),
        )
        self.logger.info(
            "OTCS Backend URL           = %s",
            str(self.settings.otcs.url_backend),
        )
        self.logger.info("OTCS Admin User            = %s", self.settings.otcs.username)
        self.logger.debug(
            "OTCS Admin Password        = %s",
            self.settings.otcs.password,
        )
        self.logger.info(
            "OTCS User Partition        = %s",
            self.settings.otcs.partition,
        )
        self.logger.info(
            "OTCS Resource Name         = %s",
            self.settings.otcs.resource_name,
        )
        self.logger.info(
            "OTCS User Default License  = %s",
            self.settings.otcs.license_feature,
        )
        self.logger.info(
            "OTCS K8s Frontend Pods     = %s",
            self.settings.k8s.sts_otcs_frontend,
        )
        self.logger.info(
            "OTCS K8s Backend Pods      = %s",
            self.settings.k8s.sts_otcs_admin,
        )
        self.logger.info(
            "FEME URI                   = %s",
            self.settings.otcs.feme_uri,
        )

        self.logger.debug("Checking if OTCS object has already been initialized")

        otds_ticket = self.otds_object.cookie()["OTDSTicket"] if self.otds_object else None
        otcs_object = OTCS(
            url.scheme,
            url.host,
            url.port,
            self.settings.otcs.url.scheme + "://" + self.settings.otcs.url.host,
            self.settings.otcs.username,
            self.settings.otcs.password.get_secret_value(),
            self.settings.otcs.partition,
            self.settings.otcs.resource_name,
            otds_ticket=otds_ticket,
            base_path=self.settings.otcs.base_path,
            feme_uri=self.settings.otcs.feme_uri,
            logger=self.logger,
        )

        # It is important to wait for OTCS to be configured - otherwise we
        # may interfere with the OTCS container automation and run into errors
        self.logger.info("Wait for OTCS to be configured...")
        otcs_configured = otcs_object.is_configured()
        while not otcs_configured:
            self.logger.warning("OTCS is not configured yet. Waiting 30 seconds...")
            time.sleep(30)
            otcs_configured = otcs_object.is_configured()
        self.logger.info("OTCS is configured now.")

        self.logger.info("Authenticating to OTCS...")
        otcs_cookie = otcs_object.authenticate()
        while otcs_cookie is None:
            self.logger.info("Waiting 30 seconds for OTCS to become ready...")
            time.sleep(30)
            otcs_cookie = otcs_object.authenticate()
        self.logger.info("OTCS is ready now.")

        if "OTCS_RESSOURCE_ID" not in self.settings.placeholder_values:
            self.settings.placeholder_values["OTCS_RESSOURCE_ID"] = self.otds_object.get_resource(
                self.settings.otcs.resource_name,
            )["resourceID"]
            self.logger.debug(
                "Placeholder values after OTCS init -> %s",
                self.settings.placeholder_values,
            )

        if self.settings.otawp.enabled:
            otcs_resource = self.otds_object.get_resource(
                self.settings.otcs.resource_name,
            )
            otcs_resource["logoutURL"] = (
                f"{self.settings.otawp.public_protocol}://{self.settings.otawp.public_url}/home/system/wcp/sso/sso_logout.htm"
            )
            otcs_resource["logoutMethod"] = "GET"

            self.otds_object.update_resource(name="cs", resource=otcs_resource)

        # Allow impersonation of the resource for all users:
        self.otds_object.impersonate_resource(self.settings.otcs.resource_name)

        return otcs_object

    # end method definition

    def init_otiv(self) -> OTIV | None:
        """Initialize the OTIV (Intelligent Viewing) object and its OTDS settings.

        Args:
            None

        Returns:
            OTIV:
                The OTIV object.

        """

        self.logger.info("Parameters for OTIV (Intelligent Viewing):")
        self.logger.info(
            "OTDS Resource Name       = %s",
            self.settings.otiv.resource_name,
        )
        self.logger.info(
            "OTIV License File        = %s",
            self.settings.otiv.license_file,
        )
        self.logger.info(
            "OTIV Product Name        = %s",
            self.settings.otiv.product_name,
        )
        self.logger.info(
            "OTIV Product Description = %s",
            self.settings.otiv.product_description,
        )
        self.logger.info(
            "OTIV License Feature     = %s",
            self.settings.otiv.license_feature,
        )

        otiv_object = OTIV(
            resource_name=self.settings.otiv.resource_name,
            product_name=self.settings.otiv.product_name,
            product_description=self.settings.otiv.product_description,
            license_file=self.settings.otiv.license_file,
            default_license=self.settings.otiv.license_feature,
            logger=self.logger,
        )

        otiv_resource = self.otds_object.get_resource(self.settings.otiv.resource_name)
        while otiv_resource is None:
            self.logger.info(
                "OTDS Resource -> %s for Intelligent Viewing not found. OTIV may not be ready. Wait 30 sec...",
                self.settings.otiv.resource_name,
            )
            time.sleep(30)
            otiv_resource = self.otds_object.get_resource(
                self.settings.otiv.resource_name,
            )

        otiv_license = self.otds_object.add_license_to_resource(
            self.settings.otiv.license_file,
            self.settings.otiv.product_name,
            self.settings.otiv.product_description,
            otiv_resource["resourceID"],
        )
        if not otiv_license:
            self.logger.info(
                "Couldn't apply license -> %s for product -> %s. Intelligent Viewing may not be deployed!",
                self.settings.otiv.license_file,
                self.settings.otiv.product_name,
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

        self.logger.info("OTDS user iv-publisher -> updating oTType=ServiceUser")

        return otiv_object

    # end method definition

    def init_otpd(self) -> OTPD:
        """Initialize the OTPD (PowerDocs) object and parameters.

        Args:
            None

        Returns:
            OTPD:
                The OTPD (PowerDocs) object.

        """

        self.logger.info("Connection parameters OTPD (PowerDocs):")
        self.logger.info(
            "OTPD Protocol             = %s",
            self.settings.otpd.url.scheme,
        )
        self.logger.info("OTPD Hostname             = %s", self.settings.otpd.url.host)
        self.logger.info("OTPD Port                 = %s", self.settings.otpd.url.port)
        self.logger.info("OTPD API User             = %s", self.settings.otpd.username)
        self.logger.info("OTPD Tenant               = %s", self.settings.otpd.tenant)
        self.logger.info(
            "OTPD Database Import File = %s",
            (self.settings.otpd.db_importfile if self.settings.otpd.db_importfile != "" else "<not configured>"),
        )
        self.logger.info("OTPD K8s Pod Name         = %s", self.settings.k8s.pod_otpd)

        otpd_object = OTPD(
            self.settings.otpd.url.scheme,
            self.settings.otpd.url.host,
            self.settings.otpd.url.port,
            self.settings.otpd.username,
            self.settings.otpd.password,
            logger=self.logger,
        )

        # wait until the OTPD pod is in ready state
        self.k8s_object.wait_pod_condition(self.settings.k8s.pod_otpd, "Ready")

        # We have a race condition here. Even if the pod is ready
        # it may not yet have fully initialized its database.
        # Then the "apply_setting()" calls below may fail with
        # an error. This should be improved in the future. For now
        # we just wait a minute hoping that the DB is initialized then.
        #        self.logger.info("Wait some time for PowerDocs database to be initialized...")
        #        time.sleep(60)
        #        self.logger.info("Configure some basic PowerDocs settings...")

        # Fix settings for local Kubernetes deployments.
        # Unclear why this is not the default.
        # if otpd_object:
        #     otpd_object.apply_setting("LocalOtdsUrl", "http://otds/otdsws")
        #     otpd_object.apply_setting(
        #         "LocalApplicationServerUrlForContentManager",
        #         "http://localhost:8080/c4ApplicationServer",
        #         self.settings.otpd.tenant,
        #     )

        return otpd_object

        # end function definition

    def init_otawp(self) -> OTAWP:
        """Initialize OTDS for Appworks Platform.

        Returns:
            OTAWP:
                The AppWorks Platform object.

        """

        self.logger.info("Connection parameters OTAWP:")
        self.logger.info(
            "OTAWP Enabled          = %s",
            str(self.settings.otawp.enabled),
        )
        self.logger.info(
            "OTAWP Resource         = %s",
            self.settings.otawp.resource_name,
        )
        self.logger.info(
            "OTAWP Access Role      = %s",
            self.settings.otawp.access_role_name,
        )
        self.logger.info("OTAWP Admin User       = %s", self.settings.otawp.username)
        self.logger.debug("OTAWP Password        = %s", self.settings.otawp.password)
        self.logger.info("OTAWP K8s Stateful Set = %s", self.settings.k8s.sts_otawp)
        self.logger.info("OTAWP K8s Config Map   = %s", self.settings.k8s.cm_otawp)

        self.logger.info(
            "Wait for OTCS to create its OTDS resource with name -> '%s'...",
            self.settings.otcs.resource_name,
        )

        # Loop to wait for OTCS to create its OTDS resource
        # (we need it to update the AppWorks K8s Config Map):
        otcs_resource = self.otds_object.get_resource(self.settings.otcs.resource_name)
        while otcs_resource is None:
            self.logger.warning(
                "OTDS resource for Content Server with name -> '%s' does not exist yet. Waiting...",
                self.settings.otcs.resource_name,
            )
            time.sleep(30)
            otcs_resource = self.otds_object.get_resource(
                self.settings.otcs.resource_name,
            )

        otcs_resource_id = otcs_resource["resourceID"]

        self.logger.info("Found Content Server OTDS resource ID -> %s", otcs_resource_id)

        # make sure code is idempotent and only try to add ressource if it doesn't exist already:
        awp_resource = self.otds_object.get_resource(self.settings.otawp.resource_name)
        if not awp_resource:
            self.logger.info(
                "OTDS resource -> '%s' for AppWorks Platform does not yet exist. Creating...",
                self.settings.otawp.resource_name,
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
                {"name": "fUsername", "value": self.settings.otawp.username},
                {
                    "name": "fPassword",
                    "value": self.settings.otawp.password.get_secret_value(),
                },
            ]

            awp_resource = self.otds_object.add_resource(
                name=self.settings.otawp.resource_name,
                description="AppWorks Platform",
                display_name="AppWorks Platform",
                additional_payload=additional_payload,
            )
        else:
            self.logger.info(
                "OTDS resource -> '%s' for AppWorks Platform does already exist.",
                self.settings.otawp.resource_name,
            )

        awp_resource_id = awp_resource["resourceID"]

        self.logger.info(
            "OTDS resource ID for AppWorks Platform -> %s",
            awp_resource_id,
        )

        self.settings.placeholder_values["OTAWP_RESOURCE_ID"] = str(awp_resource_id)

        self.logger.debug(
            "Placeholder values after OTAWP init = %s",
            self.settings.placeholder_values,
        )

        self.logger.info(
            "Update AppWorks Kubernetes Config Map with OTDS resource IDs...",
        )

        config_map = self.k8s_object.get_config_map(self.settings.k8s.cm_otawp)
        if not config_map:
            self.logger.error(
                "Failed to retrieve AppWorks Kubernetes Config Map -> %s",
                self.settings.k8s.cm_otawp,
            )
        else:
            solution = yaml.safe_load(config_map.data["solution.yaml"])

            # Change values as required
            solution["platform"]["organizations"]["system"]["otds"]["resourceId"] = awp_resource_id
            solution["platform"]["content"]["ContentServer"]["contentServerUrl"] = (
                f"{self.settings.otcs.url!s}{self.settings.otcs.base_path}"
            )
            solution["platform"]["content"]["ContentServer"]["contentServerSupportDirectoryUrl"] = (
                f"{self.settings.otcs.url!s}/cssupport"
            )
            solution["platform"]["content"]["ContentServer"]["otdsResourceId"] = otcs_resource_id
            solution["platform"]["authenticators"]["OTDS_auth"]["publicLoginUrl"] = (
                str(self.settings.otds.url) + "/otdsws/login"
            )
            solution["platform"]["security"]["contentSecurityPolicy"] = "frame-ancestors 'self' " + str(
                self.settings.otcs.url,
            )
            config_map.data["solution.yaml"] = yaml.dump(solution)
            result = self.k8s_object.replace_config_map(
                self.settings.k8s.cm_otawp,
                config_map.data,
            )
            if result:
                self.logger.info("Successfully updated AppWorks solution YAML.")
            else:
                self.logger.error("Failed to update AppWorks Solution YAML.")
            self.logger.debug("Solution YAML for AppWorks -> %s", solution)

        self.logger.info("Scale AppWorks Kubernetes Stateful Set to 1...")
        self.k8s_object.scale_stateful_set(
            sts_name=self.settings.k8s.sts_otawp,
            scale=1,
        )

        # Add the OTCS Admin user to the AppWorks Access Role in OTDS
        self.otds_object.add_user_to_access_role(
            "Access to " + self.settings.otawp.resource_name,
            "otadmin@otds.admin",
        )

        # Loop to wait for OTCS to create its OTDS user partition:
        otcs_partition = self.otds_object.get_partition(
            self.settings.otcs.partition,
            show_error=False,
        )
        while otcs_partition is None:
            self.logger.warning(
                "OTDS user partition for Content Server with name -> '%s' does not exist yet. Waiting...",
                self.settings.otcs.partition,
            )

            time.sleep(30)
            otcs_partition = self.otds_object.get_partition(
                self.settings.otcs.partition,
                show_error=False,
            )

        # Add the OTDS user partition for OTCS to the AppWorks Platform Access Role in OTDS.
        # This will effectvely sync all OTCS users with AppWorks Platform:
        self.otds_object.add_partition_to_access_role(
            self.settings.otawp.access_role_name,
            self.settings.otcs.partition,
        )

        # Add the OTDS admin partition to the AppWorks Platform Access Role in OTDS.
        self.otds_object.add_partition_to_access_role(
            self.settings.otawp.access_role_name,
            self.settings.otds.admin_partition,
        )

        # Set Group inclusion for Access Role for OTAWP to "True":
        self.otds_object.update_access_role_attributes(
            self.settings.otawp.access_role_name,
            [{"name": "pushAllGroups", "values": ["True"]}],
        )

        # Add ResourceID User to OTDSAdmin to allow push
        self.otds_object.add_user_to_group(
            user=str(awp_resource_id) + "@otds.admin",
            group="otdsadmins@otds.admin",
        )

        # Allow impersonation for all users:
        self.otds_object.impersonate_resource(self.settings.otawp.resource_name)

        # Add SPS license for OTAWP
        # check if the license file exists, otherwise skip for versions pre 24.1
        if os.path.isfile(self.settings.otawp.license_file):
            self.logger.info(
                "Found OTAWP license file -> '%s', assiging it to ressource '%s'...",
                self.settings.otawp.license_file,
                self.settings.otawp.resource_name,
            )

            otawp_license = self.otds_object.add_license_to_resource(
                self.settings.otawp.license_file,
                self.settings.otawp.product_name,
                self.settings.otawp.product_description,
                awp_resource["resourceID"],
            )
            if not otawp_license:
                self.logger.error(
                    "Couldn't apply license -> '%s' for product -> '%s' to OTDS resource -> '%s'",
                    self.settings.otawp.license_file,
                    self.settings.otawp.product_name,
                    awp_resource["resourceID"],
                )
            else:
                self.logger.info(
                    "Successfully applied license -> '%s' for product -> '%s' to OTDS resource -> '%s'",
                    self.settings.otawp.license_file,
                    self.settings.otawp.product_name,
                    awp_resource["resourceID"],
                )

            # Assign AppWorks license to Content Server Members Partiton and otds.admin:
            for partition_name in ["otds.admin", self.settings.otcs.partition]:
                if self.otds_object.is_partition_licensed(
                    partition_name=partition_name,
                    resource_id=awp_resource["resourceID"],
                    license_feature="USERS",
                    license_name=self.settings.otawp.product_name,
                ):
                    self.logger.info(
                        "Partition -> '%s' is already licensed for -> '%s' (%s)",
                        partition_name,
                        self.settings.otawp.product_name,
                        "USERS",
                    )
                else:
                    assigned_license = self.otds_object.assign_partition_to_license(
                        partition_name,
                        awp_resource["resourceID"],
                        "USERS",
                        self.settings.otawp.product_name,
                    )
                    if not assigned_license:
                        self.logger.error(
                            "Partition -> '%s' could not be assigned to license -> '%s' (%s)",
                            partition_name,
                            self.settings.otawp.product_name,
                            "USERS",
                        )
                    else:
                        self.logger.info(
                            "Partition -> '%s' successfully assigned to license -> '%s' (%s)",
                            partition_name,
                            self.settings.otawp.product_name,
                            "USERS",
                        )
        otawp_object = OTAWP(
            self.settings.otawp.protocol,
            self.settings.k8s.sts_otawp,
            str(self.settings.otawp.port),
            "sysadmin",
            self.settings.otawp.password.get_secret_value(),
            "",
            self.settings.otcs.partition,
            self.settings.otds.admin_partition,
            self.settings.k8s.cm_otawp,
            otcs_resource_id,
            self.settings.otds.url,
            self.settings.otcs.url,
            self.settings.otcs.base_path,
            self.settings.otawp.license_file,
            self.settings.otawp.product_name,
            self.settings.otawp.product_description,
            logger=self.logger,
        )
        return otawp_object

    # end method definition

    def restart_otcs_service(
        self,
        backend: OTCS,
        frontend: OTCS,
        extra_wait_time: int = 60,
    ) -> None:
        """Restart the Content Server service in all OTCS pods.

        Args:
            backend:
                OTCS object of the backend.
            frontend:
                OTCS object of the frontend.
            extra_wait_time (int):
                Extra wait time after the restart to make sure pods are responsive again.

        Returns:
            None

        """

        if not self.k8s_object:
            self.logger.warning(
                "Kubernetes integration not available, skipping restart of services",
            )
            return

        self.logger.info("Restart OTCS frontend and backend pods...")

        # Restart all frontends:
        for x in range(self.settings.k8s.sts_otcs_frontend_replicas):
            pod_name = self.settings.k8s.sts_otcs_frontend + "-" + str(x)

            self.logger.info("Deactivate Liveness probe for pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "touch /tmp/keepalive"],
                container="otcs-frontend-container",
            )
            self.logger.info("Restarting pod -> '%s'", pod_name)
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
        for x in range(self.settings.k8s.sts_otcs_admin_replicas):
            pod_name = self.settings.k8s.sts_otcs_admin + "-" + str(x)

            self.logger.info("Deactivate Liveness probe for pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "touch /tmp/keepalive"],
                container="otcs-admin-container",
            )
            self.logger.info("Restarting pod -> '%s'", pod_name)
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

        # Reauthenticate at frontend:
        self.logger.info(
            "Re-Authenticating to OTCS frontend after restart of frontend pods...",
        )
        otcs_cookie = frontend.authenticate(revalidate=True)
        while otcs_cookie is None:
            self.logger.info("Waiting 30 seconds for OTCS frontend to become ready...")
            time.sleep(30)
            otcs_cookie = frontend.authenticate(revalidate=True)
        self.logger.info("OTCS frontend is ready again.")

        # Reauthenticate at backend:
        self.logger.info(
            "Re-Authenticating to OTCS backend after restart of backend pods...",
        )
        otcs_cookie = backend.authenticate(revalidate=True)
        while otcs_cookie is None:
            self.logger.info("Waiting 30 seconds for OTCS backend to become ready...")
            time.sleep(30)
            otcs_cookie = backend.authenticate(revalidate=True)
        self.logger.info("OTCS backend is ready again.")

        # Reactivate Liveness probes in all pods:
        for x in range(self.settings.k8s.sts_otcs_frontend_replicas):
            pod_name = self.settings.k8s.sts_otcs_frontend + "-" + str(x)

            self.logger.info("Reactivate Liveness probe for pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "rm /tmp/keepalive"],
                container="otcs-frontend-container",
            )

        for x in range(self.settings.k8s.sts_otcs_admin_replicas):
            pod_name = self.settings.k8s.sts_otcs_admin + "-" + str(x)

            self.logger.info("Reactivate Liveness probe for pod -> '%s'", pod_name)
            self.k8s_object.exec_pod_command(
                pod_name,
                ["/bin/sh", "-c", "rm /tmp/keepalive"],
                container="otcs-admin-container",
            )

        self.logger.info("Restart OTCS frontend and backend pods has been completed.")

        # optional, give some additional time to make sure service is responsive
        if extra_wait_time > 0:
            self.logger.info(
                "Wait %s seconds to make sure OTCS is responsive again...",
                str(extra_wait_time),
            )
            time.sleep(extra_wait_time)
        self.logger.info("Continue customizing...")

    # end method definition

    def restart_otac_service(self) -> bool:
        """Restart the Archive Center spawner service in OTAC pod.

        Returns:
            bool: True if restart was done, False if error occured.

        """

        if not self.settings.otac.enabled:
            return False

        self.logger.info(
            "Restarting spawner service in Archive Center pod -> '%s'",
            self.settings.k8s.pod_otac,
        )
        # The Archive Center Spawner needs to be run in "interactive" mode - otherwise the command will "hang":
        # The "-c" parameter is not required in this case
        # False is given as parameter as OTAC writes non-errors to stderr
        response = self.k8s_object.exec_pod_command_interactive(
            pod_name=self.settings.k8s.pod_otac,
            commands=["/bin/sh", "/etc/init.d/spawner restart"],
            timeout=60,
            write_stderr_to_error_log=False,
        )

        return bool(response)

    # end method definition

    def restart_otawp_pod(self) -> None:
        """Delete the AppWorks Platform Pod to make Kubernetes restart it."""

        self.k8s_object.delete_pod(self.settings.k8s.sts_otawp + "-0")

    # end method definition

    def consolidate_otds(self) -> None:
        """Consolidate OTDS resources."""

        self.otds_object.consolidate(self.settings.otcs.resource_name)

        if self.settings.otawp.enabled:  # is AppWorks Platform deployed?
            self.otds_object.consolidate(self.settings.otawp.resource_name)

    # end method definition

    def import_powerdocs_configuration(self, otpd_object: OTPD) -> None:
        """Import a database export (zip file) into the PowerDocs database.

        Args:
            otpd_object (OTPD):
                The PowerDocs object.

        """

        if self.settings.otpd.db_importfile.startswith("http"):
            # Download file from remote location specified by the OTPD_DBIMPORTFILE
            # this must be a public place without authentication:
            self.logger.info(
                "Download PowerDocs database file from URL -> '%s'",
                self.settings.otpd.db_importfile,
            )

            try:
                package = requests.get(self.settings.otpd.db_importfile, timeout=60)
                package.raise_for_status()
                self.logger.info(
                    "Successfully downloaded PowerDocs database file -> '%s'; status code -> %s",
                    self.settings.otpd.db_importfile,
                    package.status_code,
                )
                filename = os.path.join(tempfile.gettempdir(), "otpd_db_import.zip")
                with open(filename, mode="wb") as localfile:
                    localfile.write(package.content)

                self.logger.info(
                    "Starting import on %s://%s:%s of %s",
                    self.settings.otpd.url.scheme,
                    self.settings.otpd.url.host,
                    self.settings.otpd.url.port,
                    self.settings.otpd.db_importfile,
                )
                response = otpd_object.import_database(file_path=filename)
                self.logger.info("Response -> %s", response)

            except requests.exceptions.HTTPError:
                self.logger.error("HTTP request error!")

    # end method definition

    def set_maintenance_mode(self, enable: bool = True) -> None:
        """Enable or Disable Maintenance Mode.

        This redirects the Kubernetes Ingress to a maintenace web page.

        Args:
            enable (bool, optional):
                Whether or not to activate the maintenance mode web page.
                Defaults to True.

        """

        if enable and self.settings.k8s.enabled:
            self.log_header("Enable Maintenance Mode")
            self.logger.info(
                "Put OTCS frontends in Maitenance Mode by changing the Kubernetes Ingress backend service...",
            )
            self.k8s_object.update_ingress_backend_services(
                self.settings.k8s.ingress_otxecm,
                "otcs",
                self.settings.k8s.maintenance_service_name,
                self.settings.k8s.maintenance_service_port,
            )
            self.logger.info("OTCS frontend is now in Maintenance Mode!")
        elif not self.settings.k8s.enabled:
            self.logger.warning(
                "Kubernetes Integration disabled - Cannot Enable/Disable Maintenance Mode",
            )
            self.k8s_object = None
        else:
            # Changing the Ingress backend service to OTCS frontend service:
            self.logger.info(
                "Put OTCS frontend back in Production Mode by changing the Kubernetes Ingress backend service...",
            )
            self.k8s_object.update_ingress_backend_services(
                self.settings.k8s.ingress_otxecm,
                "otcs",
                self.settings.otcs.url_frontend.host,
                self.settings.otcs.url_frontend.port,
            )
            self.logger.info("OTCS frontend is now back in Production Mode!")

    # end method definition

    def init_customizer(self) -> bool:
        """Initialize all objects used by the customizer.

        This includes:
        * OTDS
        * Kubernetes (K8S)
        * AppWorks Platform
        * OTCS (frontend + backend)
        * OTAC (Archive Center)
        * OTIV (Intelligent Viewing)
        * OTPD (PowerDocs)
        * Core Share
        * Microsoft 365
        * Aviator Search

        Returns:
            bool:
                True = success. False = error.

        """

        self.log_header("Initialize OTDS")

        self.otds_object = self.init_otds()
        if not self.otds_object:
            self.logger.error("Failed to initialize OTDS - exiting...")
            return False

        # Establish in-cluster Kubernetes connection
        self.log_header("Initialize Kubernetes")
        if self.settings.k8s.enabled:
            try:
                self.k8s_object = self.init_k8s()

                if not self.k8s_object:
                    self.logger.error("Failed to initialize Kubernetes - exiting...")
                    return False
            except Exception as err:
                self.logger.error(
                    "Failed to initialize Kubernetes, disabling Kubernetes integration...",
                )
                self.logger.debug(err)
                self.settings.k8s.enabled = False

        if self.settings.otawp.enabled:  # is AppWorks Platform deployed?
            self.log_header("Initialize OTAWP")

            # Configure required OTDS resources as AppWorks doesn't do this on its own:
            self.otawp_object = self.init_otawp()
        else:
            self.settings.placeholder_values["OTAWP_RESOURCE_ID"] = ""

        self.log_header("Initialize OTCS backend")
        self.otcs_backend_object = self.init_otcs(
            url=self.settings.otcs.url_backend,
        )
        if not self.otcs_backend_object:
            self.logger.error("Failed to initialize OTCS backend - exiting...")
            sys.exit()

        self.log_header("Initialize OTCS frontend")
        self.otcs_frontend_object = self.init_otcs(
            url=self.settings.otcs.url_frontend,
        )
        if not self.otcs_frontend_object:
            self.logger.error("Failed to initialize OTCS frontend - exiting...")
            return False

        if self.settings.otac.enabled:  # is Archive Center deployed?
            self.log_header("Initialize OTAC")

            self.otac_object = self.init_otac()
            if not self.otac_object:
                self.logger.error("Failed to initialize OTAC - exiting...")
                return False
        else:
            self.otac_object = None

        if self.settings.otiv.enabled:  # is Intelligent Viewing deployed?
            self.log_header("Initialize OTIV")

            self.otiv_object = self.init_otiv()
        else:
            self.otiv_object = None

        if self.settings.otpd.enabled:  # is PowerDocs deployed?
            self.log_header("Initialize OTPD")

            self.otpd_object = self.init_otpd()
            if not self.otpd_object:
                self.logger.error("Failed to initialize OTPD - exiting...")
                return False
        else:
            self.otpd_object = None

        if self.settings.coreshare.enabled:  # is Core Share enabled?
            self.log_header("Initialize Core Share")

            self.core_share_object = self.init_coreshare()
            if not self.core_share_object:
                self.logger.error("Failed to initialize Core Share - exiting...")
                return False
        else:
            self.core_share_object = None

        if (
            self.settings.m365.enabled and self.settings.m365.username != "" and self.settings.m365.password != ""
        ):  # is M365 enabled?
            self.log_header("Initialize Microsoft 365")

            # Initialize the M365 object and connection to M365 Graph API:
            self.m365_object = self.init_m365()
            if not self.m365_object:
                self.logger.error("Failed to initialize Microsoft 365!")
                return False

        if self.settings.avts.enabled:
            self.log_header("Initialize Aviator Search")
            self.avts_object = self.init_avts()
            if not self.avts_object:
                self.logger.error("Failed to initialize Aviator Search")
                return False
        else:
            self.avts_object = None

        return True

    # end method definition

    def customization_run(self) -> bool:
        """Central method to initiate the customization."""

        success = True

        # Set Timer for duration calculation
        self.customizer_start_time = datetime.now(timezone.utc)

        if not self.init_customizer():
            self.logger.error("Initialization of customizer failed!")
            return False

        # Put Frontend in Maintenance mode to make sure nobody interferes
        # during customization:
        if self.settings.otcs.maintenance_mode:
            self.set_maintenance_mode(enable=True)

        self.log_header("Collect payload files to process")

        cust_payload_list = []
        # Is uncompressed payload provided?
        if self.settings.cust_payload and os.path.exists(self.settings.cust_payload):
            self.logger.info("Found payload file -> '%s'", self.settings.cust_payload)
            cust_payload_list.append(self.settings.cust_payload)
        # Is compressed payload provided?
        if self.settings.cust_payload_gz and os.path.exists(
            self.settings.cust_payload_gz,
        ):
            self.logger.info(
                "Found compressed payload file -> '%s'",
                self.settings.cust_payload_gz,
            )
            cust_payload_list.append(self.settings.cust_payload_gz)

        # do we have additional payload as an external file?
        if self.settings.cust_payload_external and os.path.exists(
            self.settings.cust_payload_external,
        ):
            for filename in sorted(
                os.scandir(self.settings.cust_payload_external),
                key=lambda e: e.name,
            ):
                if filename.is_file() and os.path.getsize(filename) > 0:
                    self.logger.info(
                        "Found external payload file -> '%s'",
                        filename.path,
                    )
                    cust_payload_list.append(filename.path)
        elif self.settings.cust_payload_external:
            self.logger.warning(
                "External payload file -> '%s' does not exist!",
                self.settings.cust_payload_external,
            )

        for cust_payload in cust_payload_list:
            self.log_header("Start processing of payload -> '{}'".format(cust_payload))

            # Set startTime for duration calculation
            start_time = datetime.now(timezone.utc)

            # Create payload object:
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
                otpd_object=self.otpd_object,
                m365_object=self.m365_object,
                core_share_object=self.core_share_object,
                browser_automation_object=self.browser_automation_object,
                placeholder_values=self.settings.placeholder_values,  # this dict includes placeholder replacements for the Ressource IDs of OTAWP and OTCS
                log_header_callback=self.log_header,
                stop_on_error=self.settings.stop_on_error,
                aviator_enabled=self.settings.aviator.enabled,
                upload_status_files=self.settings.otcs.upload_status_files,
                otawp_object=self.otawp_object,
                avts_object=self.avts_object,
                logger=self.logger,
            )
            # Load the payload file and initialize the payload sections:
            if not payload_object.init_payload():
                self.logger.error(
                    "Failed to initialize payload -> '%s' - skipping payload file...",
                    cust_payload,
                )
                success = False
                continue

            # Now process the payload in the defined ordering:
            payload_object.process_payload()

            self.log_header("Consolidate OTDS Resources")
            self.consolidate_otds()

            # Upload payload file for later review to Enterprise Workspace
            if self.settings.otcs.upload_config_files:
                self.log_header("Upload Payload file to Extended ECM")
                response = self.otcs_backend_object.get_node_from_nickname(
                    nickname=self.settings.cust_target_folder_nickname,
                )
                target_folder_id = self.otcs_backend_object.get_result_value(
                    response=response,
                    key="id",
                )
                if not target_folder_id:
                    target_folder_id = 2000  # use Enterprise Workspace as fallback
                # Write YAML file with upadated payload (including IDs, etc.).
                # We need to write to a temporary location as initial location is read-only:
                payload_file = os.path.basename(cust_payload)
                payload_file = payload_file.removesuffix(".gz.b64")
                payload_file = payload_file.replace(".tfvars", ".yaml").replace(
                    ".tf",
                    ".yaml",
                )
                cust_payload = os.path.join(tempfile.gettempdir(), payload_file)

                with open(cust_payload, "w", encoding="utf-8") as file:
                    yaml.dump(
                        data=payload_object.get_payload(
                            drop_bulk_datasources_data=True,
                        ),
                        stream=file,
                    )

                # Check if the payload file has been uploaded before.
                # This can happen if we re-run the python container.
                # In this case we add a version to the existing document:
                response = self.otcs_backend_object.get_node_by_parent_and_name(
                    parent_id=int(target_folder_id),
                    name=os.path.basename(cust_payload),
                )
                target_document_id = self.otcs_backend_object.get_result_value(
                    response=response,
                    key="id",
                )
                if target_document_id:
                    response = self.otcs_backend_object.add_document_version(
                        node_id=int(target_document_id),
                        file_url=cust_payload,
                        file_name=os.path.basename(cust_payload),
                        mime_type="text/plain",
                        description="Updated payload file after re-run of customization",
                    )
                else:
                    response = self.otcs_backend_object.upload_file_to_parent(
                        file_url=cust_payload,
                        file_name=os.path.basename(cust_payload),
                        mime_type="text/plain",
                        parent_id=int(target_folder_id),
                    )

            duration = datetime.now(timezone.utc) - start_time
            self.log_header(
                "Customizer completed processing of payload -> {} in {}".format(
                    cust_payload,
                    duration,
                ),
            )
        # end for cust_payload in cust_payload_list

        if self.settings.otcs.maintenance_mode:
            self.set_maintenance_mode(enable=False)

        # Restart AppWorksPlatform pod if it is deployed (to make settings effective):
        if self.settings.otawp.enabled:  # is AppWorks Platform deployed?
            otawp_resource = self.otds_object.get_resource(
                name=self.settings.otawp.resource_name,
            )
            if "allowImpersonation" not in otawp_resource or not otawp_resource["allowImpersonation"]:
                # Allow impersonation for all users:
                self.logger.warning(
                    "OTAWP impersonation is not correct in OTDS before OTAWP pod restart!",
                )
            else:
                self.logger.info(
                    "OTAWP impersonation is correct in OTDS before OTAWP pod restart!",
                )
            self.logger.info("Restart OTAWP pod...")
            self.restart_otawp_pod()
            # For some reason we need to double-check that the impersonation
            # for OTAWP has been set correctly and if not set it again:
            otawp_resource = self.otds_object.get_resource(
                name=self.settings.otawp.resource_name,
            )
            if "allowImpersonation" not in otawp_resource or not otawp_resource["allowImpersonation"]:
                # Allow impersonation for all users:
                self.logger.warning(
                    "OTAWP impersonation is not correct in OTDS - set it once more...",
                )
                self.otds_object.impersonate_resource(
                    resource_name=self.settings.otawp.resource_name,
                )

        # Restart Aviator Search (Omnigroup) to ensure group synchronisation is working
        if self.settings.avts.enabled:  # is Aviator Search deployed?
            self.logger.info(
                "Restarting Aviator Search Omnigroup server after creation of OTDS ClientID/ClientSecret...",
            )
            self.k8s_object.restart_stateful_set(sts_name="idol-omnigroupserver")

        # Upload log file for later review to "Deployment" folder
        # in "Administration" folder in OTCS Enterprise volume:
        if os.path.exists(self.settings.cust_log_file) and self.settings.otcs.upload_log_file:
            self.log_header("Upload log file to Extended ECM")
            response = self.otcs_backend_object.get_node_from_nickname(
                nickname=self.settings.cust_target_folder_nickname,
            )
            target_folder_id = self.otcs_backend_object.get_result_value(
                response=response,
                key="id",
            )
            if not target_folder_id:
                target_folder_id = 2000  # use Enterprise Workspace as fallback
            # Check if the log file has been uploaded before.
            # This can happen if we re-run the python container:
            # In this case we add a version to the existing document:
            response = self.otcs_backend_object.get_node_by_parent_and_name(
                parent_id=int(target_folder_id),
                name=os.path.basename(self.settings.cust_log_file),
            )
            target_document_id = self.otcs_backend_object.get_result_value(
                response=response,
                key="id",
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

        self.customizer_end_time = datetime.now(timezone.utc)
        self.log_header(
            "Customizer completed in {}".format(
                self.customizer_end_time - self.customizer_start_time,
            ),
        )

        # Return the success status:
        return success

    # end method definition

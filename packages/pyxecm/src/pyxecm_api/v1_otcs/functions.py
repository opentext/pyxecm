"""Define functions for v1_otcs."""

import logging
from datetime import UTC, datetime
from threading import Lock

from fastapi import APIRouter
from pyxecm_customizer.k8s import K8s

from pyxecm_api.settings import CustomizerAPISettings

router = APIRouter(prefix="/api/v1/otcs", tags=["otcs"])

logger = logging.getLogger("pyxecm_api.v1_otcs")


def collect_otcs_logs(host: str, k8s_object: K8s, logs_lock: Lock, settings: CustomizerAPISettings) -> None:
    """Collect the logs for the given OTCS instance."""

    with logs_lock:
        timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%d_%H-%M")
        tgz_file = f"/tmp/{timestamp}_{host}.tar.gz"  # noqa: S108

        if host.startswith("otcs-frontend"):
            container = "otcs-frontend-container"
        elif host.startswith("otcs-backend-search"):
            container = "otcs-backend-search-container"
        elif host.startswith("otcs-admin"):
            container = "otcs-admin-container"
        elif host.startswith("otcs-da"):
            container = "otcs-da-container"
        else:
            container = None

        logger.info("Collecting logs for %s", host)
        k8s_object.exec_pod_command(
            pod_name=host,
            command=["tar", "-czvf", tgz_file, "/opt/opentext/cs/logs", "/opt/opentext/cs_persist/contentserver.log"],
            container=container,
            timeout=1800,
        )

        logger.info("Uploading logs for %s", host)
        k8s_object.exec_pod_command(
            pod_name=host,
            command=[
                "curl",
                "-X",
                "POST",
                "-F",
                f"file=@{tgz_file}",
                f"{settings.upload_url}?key={settings.upload_key}",
            ],
            container=container,
            timeout=1800,
        )

        logger.info("Cleanup logs for %s", host)
        k8s_object.exec_pod_command(
            pod_name=host,
            command=["rm", tgz_file],
            container=container,
        )

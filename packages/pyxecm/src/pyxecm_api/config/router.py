"""Define router for the ConfigMaps, Secrets and workloads of the namespace.

Only included when the setting pod_access is on (it follows ws_terminal): these endpoints give
the same access to the namespace as a terminal in it. A Secret's values are not part of its
listing: each value is read on its own, when it is asked for.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import base64
import logging
from http import HTTPStatus
from typing import Annotated

import anyio
from fastapi import APIRouter, Body, Depends, HTTPException
from kubernetes.client.exceptions import ApiException
from pyxecm_customizer.k8s import K8s

from pyxecm_api.auth.functions import get_authorized_user
from pyxecm_api.auth.models import User
from pyxecm_api.common.functions import get_k8s_object

from .functions import (
    RestartRunner,
    apply_update,
    check_key_name,
    check_object_name,
    collect_usage,
    config_object,
    inspect_certificate,
    list_objects,
    list_workloads,
    object_values,
    read_object,
    replace_object,
    self_workload,
    workload_model,
)
from .models import (
    CertificateInspection,
    CertificateInspectRequest,
    ConfigList,
    ConfigObject,
    ConfigUpdate,
    RestartJob,
    RestartRequest,
    SecretValue,
    WorkloadList,
)

router = APIRouter(tags=["config"])

logger = logging.getLogger("pyxecm_api.config")

RESTARTS = RestartRunner()


async def _list(k8s: K8s, kind: str) -> ConfigList:
    def read() -> ConfigList:
        items = list_objects(k8s, kind)
        try:
            usage = collect_usage(k8s)
        except ApiException as error:
            raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail="Cannot list the workloads") from error
        return ConfigList(namespace=k8s.get_namespace(), items=[config_object(item, usage) for item in items])

    return await anyio.to_thread.run_sync(read)


async def _get(k8s: K8s, kind: str, name: str) -> ConfigObject:
    check_object_name(name)

    def read() -> ConfigObject:
        obj = read_object(k8s, kind, name)
        return config_object(obj, collect_usage(k8s), include_values=kind == "ConfigMap")

    return await anyio.to_thread.run_sync(read)


async def _update(k8s: K8s, kind: str, name: str, update: ConfigUpdate, user: User) -> ConfigObject:
    check_object_name(name)

    def change() -> ConfigObject:
        obj = read_object(k8s, kind, name)
        apply_update(obj, update)
        written = replace_object(k8s, obj)
        logger.info(
            "User -> '%s' changed %s -> '%s': set %s, deleted %s",
            user.id,
            kind,
            name,
            sorted([*update.set, *update.set_base64]),
            sorted(update.delete),
        )
        return config_object(written, collect_usage(k8s), include_values=kind == "ConfigMap")

    return await anyio.to_thread.run_sync(change)


# ConfigMaps


@router.get(path="/api/v1/configmaps")
async def get_configmaps(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
) -> ConfigList:
    """List the ConfigMaps of the namespace: their keys (without values) and what uses them."""

    return await _list(k8s_object, "ConfigMap")


@router.get(path="/api/v1/configmaps/{name}")
async def get_configmap(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    name: str,
) -> ConfigObject:
    """Get a ConfigMap with its values."""

    return await _get(k8s_object, "ConfigMap", name)


@router.patch(path="/api/v1/configmaps/{name}")
async def update_configmap(
    user: Annotated[User, Depends(get_authorized_user)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    name: str,
    update: Annotated[ConfigUpdate, Body()],
) -> ConfigObject:
    """Set and delete keys of a ConfigMap.

    The change is based on the resource version the ConfigMap had when it was read: if it was
    changed since, nothing is changed (409).
    """

    return await _update(k8s_object, "ConfigMap", name, update, user)


# Secrets


@router.get(path="/api/v1/secrets")
async def get_secrets(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
) -> ConfigList:
    """List the Secrets of the namespace: their keys and certificates, never their values.

    Helm's release records (type helm.sh/release.v1) are left out.
    """

    return await _list(k8s_object, "Secret")


@router.get(path="/api/v1/secrets/{name}")
async def get_secret(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    name: str,
) -> ConfigObject:
    """Get a Secret: its keys and certificates, without values."""

    return await _get(k8s_object, "Secret", name)


@router.get(path="/api/v1/secrets/{name}/keys/{key}")
async def get_secret_value(
    user: Annotated[User, Depends(get_authorized_user)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    name: str,
    key: str,
) -> SecretValue:
    """Get the value of one key of a Secret."""

    check_object_name(name)
    check_key_name(key)
    obj = await anyio.to_thread.run_sync(read_object, k8s_object, "Secret", name)
    values = object_values(obj)
    if key not in values:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Secret '{}' has no key '{}'".format(name, key))
    raw = values[key]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    logger.info("User -> '%s' read key -> '%s' of secret -> '%s'", user.id, key, name)
    return SecretValue(name=name, key=key, value_base64=base64.b64encode(raw).decode(), text=text)


@router.patch(path="/api/v1/secrets/{name}")
async def update_secret(
    user: Annotated[User, Depends(get_authorized_user)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    name: str,
    update: Annotated[ConfigUpdate, Body()],
) -> ConfigObject:
    """Set and delete keys of a Secret.

    The change is based on the resource version the Secret had when it was read: if it was
    changed since, nothing is changed (409). A TLS Secret keeps a certificate (tls.crt) and the
    private key that belongs to it (tls.key) - 422 otherwise.
    """

    return await _update(k8s_object, "Secret", name, update, user)


@router.post(path="/api/v1/certificates/inspect")
async def post_certificate_inspect(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    request: Annotated[CertificateInspectRequest, Body()],
) -> CertificateInspection:
    """Describe a PEM certificate (chain) and private key before they are saved, and whether they belong together."""

    return inspect_certificate(request.certificate, request.private_key)


# Workloads


@router.get(path="/api/v1/workloads")
async def get_workloads(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
) -> WorkloadList:
    """List the Deployments, StatefulSets and DaemonSets of the namespace with the state of their rollout."""

    def read() -> WorkloadList:
        self_ref = self_workload(k8s_object)
        workloads = [workload_model(kind, item, self_ref) for kind, item in list_workloads(k8s_object)]
        return WorkloadList(workloads=sorted(workloads, key=lambda item: (item.name, item.kind)))

    try:
        return await anyio.to_thread.run_sync(read)
    except ApiException as error:
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail="Cannot list the workloads") from error


@router.post(path="/api/v1/workloads/restart", status_code=HTTPStatus.ACCEPTED)
async def post_workloads_restart(
    user: Annotated[User, Depends(get_authorized_user)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    request: Annotated[RestartRequest, Body()],
) -> RestartJob:
    """Restart workloads at the same time, each with a rolling restart ("kubectl rollout restart").

    All restarts start at once; the job is done when every workload is rolled out again (failed if
    one of them could not be). The job goes on in the Customizer - its state is read with its id.
    """

    refs: list[tuple[str, str]] = []
    for workload in request.workloads:
        check_object_name(workload.name)
        if (workload.kind, workload.name) not in refs:
            refs.append((workload.kind, workload.name))
    return RESTARTS.start(k8s_object, refs, user.id)


@router.get(path="/api/v1/workloads/restart/{job_id}")
async def get_workloads_restart(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    job_id: str,
) -> RestartJob:
    """Get the state of a restart job."""

    job = RESTARTS.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Restart job not found")
    return job

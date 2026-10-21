"""Define functions for the ConfigMaps, Secrets and workloads of the namespace.

What a value is (text, JSON, a certificate, binary ...) is told here, where the values are: a
Secret's values only leave the Customizer when a single key is asked for - its certificates are
described without them.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import asyncio
import base64
import binascii
import contextlib
import json
import logging
import math
import os
import re
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

import anyio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from kubernetes.client import V1ConfigMap, V1PodSpec, V1Secret
from kubernetes.client.exceptions import ApiException
from pyxecm_customizer.k8s import K8s

from pyxecm_api.pods.functions import workload_of

from .models import (
    CertificateInfo,
    CertificateInspection,
    ConfigKey,
    ConfigObject,
    ConfigUpdate,
    ConfigUsage,
    PrivateKeyInfo,
    RestartItem,
    RestartJob,
    Workload,
)

logger = logging.getLogger("pyxecm_api.config")

# Names as Kubernetes allows them: an object like a DNS subdomain, a key of its data like this.
OBJECT_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
KEY_NAME_RE = re.compile(r"^[-._a-zA-Z0-9]{1,253}$")

# Helm keeps its releases in Secrets of this type - not something to look at or change.
HELM_RELEASE_TYPE = "helm.sh/release.v1"
TLS_TYPE = "kubernetes.io/tls"
RESTARTED_AT = "kubectl.kubernetes.io/restartedAt"

# Kinds of workloads as the restart endpoint names them, and the Apps V1 calls for them.
WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet")
_API_NAMES = {"Deployment": "deployment", "StatefulSet": "stateful_set", "DaemonSet": "daemon_set"}

# A rollout that did not finish within this time (seconds) failed; and how often it is looked at.
ROLLOUT_TIMEOUT_SECONDS = 20 * 60
ROLLOUT_POLL_SECONDS = 5.0
# The restart jobs that are remembered.
MAX_JOBS = 20

PEM_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")


def check_object_name(name: str) -> str:
    """Check the name of a ConfigMap or Secret (400 if it is not one)."""

    if not OBJECT_NAME_RE.match(name):
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Invalid name: '{}'".format(name))
    return name


def check_key_name(key: str) -> str:
    """Check the name of a key of a ConfigMap or Secret (422 if it is not one)."""

    if not KEY_NAME_RE.match(key) or key in (".", ".."):
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Invalid key '{}': only letters, digits, '-', '_' and '.' are allowed".format(key),
        )
    return key


def api_error(error: ApiException, what: str) -> HTTPException:
    """Turn an error of the Kubernetes API into one of this API, with Kubernetes' message."""

    message = None
    with contextlib.suppress(ValueError, TypeError):
        message = json.loads(error.body or "{}").get("message")
    status = error.status if error.status and 400 <= error.status < 500 else HTTPStatus.BAD_GATEWAY
    if status == HTTPStatus.NOT_FOUND:
        return HTTPException(status_code=status, detail="{} not found".format(what))
    if status == HTTPStatus.CONFLICT:
        return HTTPException(status_code=status, detail="{} was changed in the meantime".format(what))
    return HTTPException(status_code=status, detail=message or "{}: {}".format(what, error.reason))


# Values: what they are


def _key_type(public_key: Any) -> str:  # noqa: ANN401
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA {}".format(public_key.key_size)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC {}".format(public_key.curve.name)
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA {}".format(public_key.key_size)
    return type(public_key).__name__


def _public_der(public_key: Any) -> bytes:  # noqa: ANN401
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def certificate_info(certificate: x509.Certificate) -> CertificateInfo:
    """Describe a certificate."""

    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    sans: list[str] = []
    with contextlib.suppress(x509.ExtensionNotFound):
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        found = [*san.get_values_for_type(x509.DNSName), *(str(ip) for ip in san.get_values_for_type(x509.IPAddress))]
        sans = list(dict.fromkeys(found))
    is_ca = False
    with contextlib.suppress(x509.ExtensionNotFound):
        is_ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    return CertificateInfo(
        subject=certificate.subject.rfc4514_string(),
        common_name=str(names[0].value) if names else None,
        issuer=certificate.issuer.rfc4514_string(),
        sans=sans,
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        serial=format(certificate.serial_number, "X"),
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(":").upper(),
        self_signed=certificate.issuer == certificate.subject,
        is_ca=is_ca,
        key_type=_key_type(certificate.public_key()),
    )


@dataclass
class PemContent:
    """The certificates and the private key of a PEM text, with their public keys to compare."""

    certificates: list[CertificateInfo] = field(default_factory=list)
    certificate_public: bytes | None = None
    private_key: PrivateKeyInfo | None = None
    private_public: bytes | None = None


def read_pem(data: bytes) -> PemContent:
    """Read the certificates and the private key of a PEM text (what cannot be read is left out)."""

    content = PemContent()
    if PEM_CERTIFICATE.encode() in data:
        with contextlib.suppress(ValueError):
            certificates = x509.load_pem_x509_certificates(data)
            content.certificates = [certificate_info(certificate) for certificate in certificates]
            content.certificate_public = _public_der(certificates[0].public_key())
    match = PEM_PRIVATE_KEY_RE.search(data.decode("ascii", errors="ignore"))
    if match:
        block = data[match.start() :]
        try:
            key = serialization.load_pem_private_key(block, password=None)
            content.private_key = PrivateKeyInfo(key_type=_key_type(key.public_key()))
            content.private_public = _public_der(key.public_key())
        except TypeError:
            # The key has a password.
            content.private_key = PrivateKeyInfo(key_type="encrypted")
        except (ValueError, binascii.Error):
            pass
    return content


def inspect_certificate(certificate: str | None, private_key: str | None) -> CertificateInspection:
    """Describe a certificate and a private key that are to be saved, and whether they belong together."""

    cert = read_pem((certificate or "").encode())
    key = read_pem((private_key or "").encode()) if private_key else cert
    error = None
    if certificate and not cert.certificates:
        error = "No certificate found - a PEM certificate starts with {}".format(PEM_CERTIFICATE)
    elif private_key and key.private_key is None:
        error = "No private key found - a PEM private key starts with -----BEGIN PRIVATE KEY-----"
    matches = None
    if cert.certificate_public and key.private_public:
        matches = cert.certificate_public == key.private_public
    return CertificateInspection(
        certificates=cert.certificates,
        private_key=key.private_key,
        key_matches=matches,
        error=error,
    )


def _text_kind(name: str, text: str) -> str:
    lower = name.lower()
    stripped = text.strip()
    if lower in (".dockerconfigjson", ".dockercfg"):
        return "docker-config"
    multiline = "\n" in text
    if lower.endswith(".json") or (multiline and stripped[:1] in ("{", "[")):
        with contextlib.suppress(ValueError):
            json.loads(text)
            return "json"
    if lower.endswith((".yaml", ".yml")):
        return "yaml"
    if lower.endswith(".xml") or stripped.startswith("<?xml"):
        return "xml"
    # A value with a line end (even only at its end) is edited as text with lines: an input field
    # would drop it.
    return "multiline" if multiline else "text"


@dataclass
class AnalyzedKey:
    """A key with what it is, and the public keys of its certificate and private key to pair them."""

    key: ConfigKey
    certificate_public: bytes | None = None
    private_public: bytes | None = None


def analyze_value(name: str, raw: bytes) -> AnalyzedKey:
    """Tell what the value of a key is."""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None or "\0" in text:
        return AnalyzedKey(ConfigKey(name=name, size=len(raw), kind="binary"))

    if "-----BEGIN" in text:
        pem = read_pem(raw)
        if pem.certificates:
            key = ConfigKey(
                name=name, size=len(raw), kind="certificate", certificates=pem.certificates, private_key=pem.private_key
            )
            return AnalyzedKey(key, pem.certificate_public, pem.private_public)
        if pem.private_key:
            key = ConfigKey(name=name, size=len(raw), kind="private-key", private_key=pem.private_key)
            return AnalyzedKey(key, private_public=pem.private_public)

    return AnalyzedKey(ConfigKey(name=name, size=len(raw), kind=_text_kind(name, text)))


def _pair_keys(analyzed: list[AnalyzedKey]) -> None:
    """Tell for each private key which key of the same object holds its certificate."""

    for item in analyzed:
        if item.private_public is None or item.key.private_key is None:
            continue
        for other in analyzed:
            if other.certificate_public == item.private_public:
                item.key.private_key.matches = other.key.name
                break


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return b""


def object_values(obj: V1ConfigMap | V1Secret) -> dict[str, bytes]:
    """Get the values of a ConfigMap or Secret by their keys, as bytes."""

    values: dict[str, bytes] = {}
    if isinstance(obj, V1Secret):
        for key, value in (obj.data or {}).items():
            values[key] = _decode(value or "")
        for key, value in (obj.string_data or {}).items():
            values[key] = (value or "").encode()
        return values
    for key, value in (obj.data or {}).items():
        values[key] = (value or "").encode()
    for key, value in (obj.binary_data or {}).items():
        values[key] = _decode(value or "")
    return values


# Who manages an object, and whether it can be changed here


def managed_by(obj: V1ConfigMap | V1Secret) -> tuple[str | None, str | None]:
    """Tell what manages an object (and may overwrite a change) and the Helm release it belongs to."""

    labels = obj.metadata.labels or {}
    annotations = obj.metadata.annotations or {}
    release = annotations.get("meta.helm.sh/release-name") or labels.get("release")
    if annotations.get("cert-manager.io/certificate-name"):
        return "cert-manager", release
    manager = labels.get("app.kubernetes.io/managed-by")
    if manager:
        return manager, release
    for owner in obj.metadata.owner_references or []:
        if owner.controller:
            return "{} {}".format(owner.kind, owner.name), release
    return None, release


def is_hidden(obj: V1ConfigMap | V1Secret) -> bool:
    """Objects that are not shown at all: Helm's own release records."""

    return isinstance(obj, V1Secret) and obj.type == HELM_RELEASE_TYPE


def read_only_reason(obj: V1ConfigMap | V1Secret) -> str | None:
    """Why an object cannot be changed here - None if it can."""

    if obj.immutable:
        return "It is immutable."
    if isinstance(obj, V1Secret) and obj.type == "kubernetes.io/service-account-token":
        return "It is the token of a service account, managed by Kubernetes."
    if isinstance(obj, V1ConfigMap) and obj.metadata.name == "kube-root-ca.crt":
        return "It is the certificate of the cluster, managed by Kubernetes."
    return None


# Where objects are used


@dataclass
class Usage:
    """The workloads and Ingresses of the namespace, and what they use."""

    configmaps: dict[str, list[ConfigUsage]] = field(default_factory=lambda: defaultdict(list))
    secrets: dict[str, list[ConfigUsage]] = field(default_factory=lambda: defaultdict(list))
    workloads: list[tuple[str, Any]] = field(default_factory=list)
    self_workload: tuple[str | None, str | None] = (None, None)


def pod_spec_refs(spec: V1PodSpec | None) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Find the ConfigMaps and Secrets a pod template uses, with how it uses them."""

    configmaps: dict[str, set[str]] = defaultdict(set)
    secrets: dict[str, set[str]] = defaultdict(set)
    if spec is None:
        return configmaps, secrets
    for volume in spec.volumes or []:
        if volume.config_map and volume.config_map.name:
            configmaps[volume.config_map.name].add("volume")
        if volume.secret and volume.secret.secret_name:
            secrets[volume.secret.secret_name].add("volume")
        for source in (volume.projected.sources or []) if volume.projected else []:
            if source.config_map and source.config_map.name:
                configmaps[source.config_map.name].add("volume")
            if source.secret and source.secret.name:
                secrets[source.secret.name].add("volume")
    for container in [*(spec.init_containers or []), *(spec.containers or [])]:
        for env in container.env or []:
            source = env.value_from
            if source and source.config_map_key_ref and source.config_map_key_ref.name:
                configmaps[source.config_map_key_ref.name].add("env")
            if source and source.secret_key_ref and source.secret_key_ref.name:
                secrets[source.secret_key_ref.name].add("env")
        for env_from in container.env_from or []:
            if env_from.config_map_ref and env_from.config_map_ref.name:
                configmaps[env_from.config_map_ref.name].add("env")
            if env_from.secret_ref and env_from.secret_ref.name:
                secrets[env_from.secret_ref.name].add("env")
    for reference in spec.image_pull_secrets or []:
        if reference.name:
            secrets[reference.name].add("image-pull")
    return configmaps, secrets


def self_workload(k8s: K8s) -> tuple[str | None, str | None]:
    """Get the workload the Customizer itself runs in (kind, name)."""

    hostname = os.environ.get("HOSTNAME")
    pod = k8s.get_pod(hostname) if hostname else None
    return workload_of(pod) if pod is not None else (None, None)


def list_workloads(k8s: K8s) -> list[tuple[str, Any]]:
    """List the Deployments, StatefulSets and DaemonSets of the namespace."""

    apps = k8s.get_apps_v1_api()
    namespace = k8s.get_namespace()
    workloads: list[tuple[str, Any]] = []
    for kind in WORKLOAD_KINDS:
        listing = getattr(apps, "list_namespaced_{}".format(_API_NAMES[kind]))(namespace)
        workloads.extend((kind, item) for item in listing.items)
    return workloads


def collect_usage(k8s: K8s) -> Usage:
    """Find what uses which ConfigMap and Secret: the workloads (by their pod template) and Ingresses."""

    usage = Usage(workloads=list_workloads(k8s), self_workload=self_workload(k8s))
    for kind, workload in usage.workloads:
        is_self = (kind, workload.metadata.name) == usage.self_workload
        configmaps, secrets = pod_spec_refs(workload.spec.template.spec if workload.spec.template else None)
        for target, refs in ((usage.configmaps, configmaps), (usage.secrets, secrets)):
            for name, via in refs.items():
                target[name].append(
                    ConfigUsage(
                        kind=kind,
                        name=workload.metadata.name,
                        via=sorted(via),
                        # A pull secret is only read when an image is pulled.
                        restartable=bool(via - {"image-pull"}),
                        is_self=is_self,
                    )
                )
    ingresses = k8s.get_networking_v1_api().list_namespaced_ingress(k8s.get_namespace())
    for ingress in ingresses.items:
        names = {tls.secret_name for tls in (ingress.spec.tls or []) if tls.secret_name}
        for name in sorted(names):
            usage.secrets[name].append(
                ConfigUsage(kind="Ingress", name=ingress.metadata.name, via=["tls"], restartable=False)
            )
    return usage


def config_object(obj: V1ConfigMap | V1Secret, usage: Usage, *, include_values: bool = False) -> ConfigObject:
    """Describe a ConfigMap or Secret. Values are only included for a ConfigMap, if asked for."""

    is_secret = isinstance(obj, V1Secret)
    values = object_values(obj)
    analyzed = [analyze_value(name, raw) for name, raw in sorted(values.items())]
    _pair_keys(analyzed)
    binary_keys = set() if is_secret else set((obj.binary_data or {}).keys())
    keys = []
    for item in analyzed:
        key = item.key
        if not is_secret and key.name in binary_keys:
            key.kind = "binary"
        if include_values and not is_secret:
            raw = values[key.name]
            if key.kind == "binary":
                key.value_base64 = base64.b64encode(raw).decode()
            else:
                key.value = raw.decode("utf-8")
        keys.append(key)

    manager, release = managed_by(obj)
    reason = read_only_reason(obj)
    name = obj.metadata.name
    return ConfigObject(
        kind="Secret" if is_secret else "ConfigMap",
        name=name,
        type=(obj.type or "Opaque") if is_secret else None,
        keys=keys,
        labels=obj.metadata.labels or {},
        managed_by=manager,
        release=release,
        created=obj.metadata.creation_timestamp,
        resource_version=obj.metadata.resource_version or "",
        read_only=reason is not None,
        read_only_reason=reason,
        used_by=list((usage.secrets if is_secret else usage.configmaps).get(name, [])),
    )


# Reading and changing objects


def read_object(k8s: K8s, kind: str, name: str) -> V1ConfigMap | V1Secret:
    """Read a ConfigMap or Secret (404 for one that does not exist or is hidden)."""

    core = k8s.get_core_v1_api()
    read = core.read_namespaced_secret if kind == "Secret" else core.read_namespaced_config_map
    try:
        obj = read(name, k8s.get_namespace())
    except ApiException as error:
        raise api_error(error, "{} '{}'".format(kind, name)) from error
    if is_hidden(obj):
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="{} '{}' not found".format(kind, name))
    return obj


def list_objects(k8s: K8s, kind: str) -> list[V1ConfigMap | V1Secret]:
    """List the ConfigMaps or Secrets of the namespace by their names, without the hidden ones."""

    core = k8s.get_core_v1_api()
    listing = core.list_namespaced_secret if kind == "Secret" else core.list_namespaced_config_map
    try:
        items = listing(k8s.get_namespace()).items
    except ApiException as error:
        raise api_error(error, "{}s".format(kind)) from error
    return sorted((item for item in items if not is_hidden(item)), key=lambda item: item.metadata.name)


def _base64_value(key: str, value: str) -> str:
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="The value of '{}' is not base64".format(key)
        ) from error
    return value


def _check_tls(values: dict[str, bytes]) -> None:
    """Check that a TLS Secret has its certificate and the private key that belongs to it."""

    certificate = read_pem(values.get("tls.crt", b""))
    key = read_pem(values.get("tls.key", b""))
    if not certificate.certificates:
        raise HTTPException(status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="tls.crt is not a PEM certificate")
    if key.private_public is None:
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="tls.key is not an unencrypted PEM private key"
        )
    if key.private_public != certificate.certificate_public:
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="tls.key does not belong to the certificate in tls.crt",
        )


def apply_update(obj: V1ConfigMap | V1Secret, update: ConfigUpdate) -> None:
    """Change the values of a ConfigMap or Secret as asked (in place)."""

    kind = "Secret" if isinstance(obj, V1Secret) else "ConfigMap"
    reason = read_only_reason(obj)
    if reason:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="{} cannot be changed: {}".format(kind, reason))
    if obj.metadata.resource_version != update.resource_version:
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail="{} '{}' was changed in the meantime".format(kind, obj.metadata.name),
        )
    changed = [*update.set, *update.set_base64]
    for key in [*changed, *update.delete]:
        check_key_name(key)
    if len(set(changed)) != len(changed) or set(changed) & set(update.delete):
        raise HTTPException(status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="A key is changed more than once")

    if isinstance(obj, V1Secret):
        data = dict(obj.data or {})
        # stringData is only written, never read back - it does not occur here.
        obj.string_data = None
        for key in update.delete:
            if key not in data:
                raise HTTPException(status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="No key '{}'".format(key))
            del data[key]
        for key, value in update.set.items():
            data[key] = base64.b64encode(value.encode()).decode()
        for key, value in update.set_base64.items():
            data[key] = _base64_value(key, value)
        obj.data = data
        if obj.type == TLS_TYPE:
            _check_tls(object_values(obj))
        return

    data = dict(obj.data or {})
    binary = dict(obj.binary_data or {})
    for key in update.delete:
        if key not in data and key not in binary:
            raise HTTPException(status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="No key '{}'".format(key))
        data.pop(key, None)
        binary.pop(key, None)
    for key, value in update.set.items():
        data[key] = value
        binary.pop(key, None)
    for key, value in update.set_base64.items():
        binary[key] = _base64_value(key, value)
        data.pop(key, None)
    obj.data = data or None
    obj.binary_data = binary or None


def replace_object(k8s: K8s, obj: V1ConfigMap | V1Secret) -> V1ConfigMap | V1Secret:
    """Write a changed ConfigMap or Secret - Kubernetes refuses it if it was changed since it was read."""

    core = k8s.get_core_v1_api()
    is_secret = isinstance(obj, V1Secret)
    replace = core.replace_namespaced_secret if is_secret else core.replace_namespaced_config_map
    name = obj.metadata.name
    try:
        return replace(name, k8s.get_namespace(), obj)
    except ApiException as error:
        raise api_error(error, "{} '{}'".format("Secret" if is_secret else "ConfigMap", name)) from error


# Workloads


def _scaled(value: Any, total: int, *, round_up: bool) -> int:  # noqa: ANN401
    """Resolve a number or percentage of pods (maxSurge, maxUnavailable)."""

    text = str(value)
    if text.endswith("%"):
        share = total * int(text[:-1]) / 100
        return math.ceil(share) if round_up else math.floor(share)
    return int(text)


def workload_model(kind: str, obj: Any, self_ref: tuple[str | None, str | None]) -> Workload:  # noqa: ANN401
    """Describe a workload and the state of its rollout."""

    spec, status, meta = obj.spec, obj.status, obj.metadata
    pending_generation = (status.observed_generation or 0) < (meta.generation or 0)
    if kind == "DaemonSet":
        replicas = status.desired_number_scheduled or 0
        ready = status.number_ready or 0
        updated = status.updated_number_scheduled or 0
        strategy_spec = spec.update_strategy
        strategy = (strategy_spec.type if strategy_spec else None) or "RollingUpdate"
        rolling_update = strategy_spec.rolling_update if strategy_spec else None
        surge = _scaled((rolling_update.max_surge if rolling_update else None) or 0, replicas, round_up=True)
        rolling = pending_generation or updated < replicas or (status.number_available or 0) < replicas
        downtime = replicas < 2 and surge == 0
    elif kind == "Deployment":
        replicas = 1 if spec.replicas is None else spec.replicas
        ready = status.ready_replicas or 0
        updated = status.updated_replicas or 0
        strategy = (spec.strategy.type if spec.strategy else None) or "RollingUpdate"
        rolling_update = spec.strategy.rolling_update if spec.strategy else None
        surge = _scaled((rolling_update.max_surge if rolling_update else None) or "25%", replicas, round_up=True)
        unavailable = _scaled(
            (rolling_update.max_unavailable if rolling_update else None) or "25%", replicas, round_up=False
        )
        rolling = (
            pending_generation
            or updated < replicas
            or (status.replicas or 0) > replicas
            or (status.available_replicas or 0) < replicas
        )
        downtime = replicas > 0 and (strategy == "Recreate" or (surge == 0 and unavailable >= replicas))
    else:
        replicas = 1 if spec.replicas is None else spec.replicas
        ready = status.ready_replicas or 0
        updated = status.updated_replicas or 0
        strategy = (spec.update_strategy.type if spec.update_strategy else None) or "RollingUpdate"
        rolling = (
            pending_generation
            or ready < replicas
            or updated < replicas
            or (status.update_revision is not None and status.current_revision != status.update_revision)
        )
        # The pods of a StatefulSet are replaced one at a time - a single one is away meanwhile.
        downtime = replicas == 1

    template = spec.template
    configmaps, secrets = pod_spec_refs(template.spec if template else None)
    annotations = (template.metadata.annotations if template and template.metadata else None) or {}
    return Workload(
        kind=kind,
        name=meta.name,
        replicas=replicas,
        ready=ready,
        updated=updated,
        rolling=bool(rolling),
        strategy=strategy,
        downtime_expected=bool(downtime),
        restarted_at=annotations.get(RESTARTED_AT),
        is_self=(kind, meta.name) == self_ref,
        configmaps=sorted(configmaps),
        secrets=sorted(secrets),
    )


def read_workload(k8s: K8s, kind: str, name: str) -> Any:  # noqa: ANN401
    """Read a workload."""

    apps = k8s.get_apps_v1_api()
    return getattr(apps, "read_namespaced_{}".format(_API_NAMES[kind]))(name, k8s.get_namespace())


def patch_restart(k8s: K8s, kind: str, name: str) -> Any:  # noqa: ANN401
    """Restart a workload the way "kubectl rollout restart" does: a new pod template, rolled out."""

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {"spec": {"template": {"metadata": {"annotations": {RESTARTED_AT: now}}}}}
    apps = k8s.get_apps_v1_api()
    return getattr(apps, "patch_namespaced_{}".format(_API_NAMES[kind]))(name, k8s.get_namespace(), body)


class RestartError(Exception):
    """A workload could not be restarted."""


def _progress_deadline_exceeded(obj: Any) -> bool:  # noqa: ANN401
    for condition in obj.status.conditions or []:
        if condition.type == "Progressing" and condition.reason == "ProgressDeadlineExceeded":
            return True
    return False


async def _wait_for(check: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + ROLLOUT_TIMEOUT_SECONDS
    while not await anyio.to_thread.run_sync(check):
        if time.monotonic() > deadline:
            message = "Timed out waiting for {}".format(what)
            raise RestartError(message)
        await asyncio.sleep(ROLLOUT_POLL_SECONDS)


def _pod_ready(pod: Any) -> bool:  # noqa: ANN401
    if pod is None or pod.metadata.deletion_timestamp:
        return False
    return any(condition.type == "Ready" and condition.status == "True" for condition in pod.status.conditions or [])


async def _restart_on_delete(k8s: K8s, name: str, replicas: int) -> None:
    """Restart a StatefulSet that only replaces pods that are deleted: one pod after the other."""

    core = k8s.get_core_v1_api()
    namespace = k8s.get_namespace()
    for ordinal in reversed(range(replicas)):
        pod_name = "{}-{}".format(name, ordinal)
        old = await anyio.to_thread.run_sync(k8s.get_pod, pod_name)
        old_uid = old.metadata.uid if old is not None else None
        try:
            await anyio.to_thread.run_sync(core.delete_namespaced_pod, pod_name, namespace)
        except ApiException as error:
            if error.status != HTTPStatus.NOT_FOUND:
                message = "Could not delete pod {}: {}".format(pod_name, error.reason)
                raise RestartError(message) from error

        def replaced(pod_name: str = pod_name, old_uid: str | None = old_uid) -> bool:
            pod = k8s.get_pod(pod_name)
            return pod is not None and pod.metadata.uid != old_uid and _pod_ready(pod)

        await _wait_for(replaced, "pod {} to be ready again".format(pod_name))


async def restart_workload(k8s: K8s, kind: str, name: str, self_ref: tuple[str | None, str | None]) -> str | None:
    """Restart a workload and wait until it is rolled out. Returns why it was skipped, if it was."""

    try:
        obj = await anyio.to_thread.run_sync(read_workload, k8s, kind, name)
    except ApiException as error:
        message = "{} {} not found".format(kind, name) if error.status == HTTPStatus.NOT_FOUND else error.reason
        raise RestartError(message) from error
    if (kind, name) == self_ref:
        return "This is the Customizer itself - restart it from its own menu."
    model = workload_model(kind, obj, self_ref)
    if model.replicas == 0:
        return "Scaled to 0 - nothing runs."

    try:
        patched = await anyio.to_thread.run_sync(patch_restart, k8s, kind, name)
    except ApiException as error:
        message = "Could not restart {} {}: {}".format(kind, name, error.reason)
        raise RestartError(message) from error

    if kind == "StatefulSet" and model.strategy == "OnDelete":
        await _restart_on_delete(k8s, name, model.replicas)
        return None

    generation = patched.metadata.generation or 0

    def rolled_out() -> bool:
        current = read_workload(k8s, kind, name)
        # Until the controller has seen the restart, a condition left from an earlier rollout counts not.
        if (current.status.observed_generation or 0) < generation:
            return False
        if kind == "Deployment" and _progress_deadline_exceeded(current):
            message = "The rollout of {} {} does not progress".format(kind, name)
            raise RestartError(message)
        return not workload_model(kind, current, self_ref).rolling

    await _wait_for(rolled_out, "the rollout of {} {}".format(kind, name))
    return None


class RestartRunner:
    """Runs restart jobs: all workloads of a job are restarted at the same time.

    Each workload is restarted with its own rolling restart, so it stays available as far as its
    replicas and update strategy allow. One that fails does not keep the others from restarting.
    """

    def __init__(self) -> None:
        """Initialize the runner without jobs."""

        self.jobs: dict[str, RestartJob] = {}
        self._tasks: set[asyncio.Task] = set()

    def start(self, k8s: K8s, workloads: list[tuple[str, str]], user: str) -> RestartJob:
        """Start a job that restarts the workloads, all at the same time."""

        job = RestartJob(
            id=uuid.uuid4().hex,
            state="running",
            started=datetime.now(UTC),
            items=[RestartItem(kind=kind, name=name, state="pending") for kind, name in workloads],
        )
        self.jobs[job.id] = job
        for old in sorted(self.jobs.values(), key=lambda item: item.started)[:-MAX_JOBS]:
            if old.state != "running":
                del self.jobs[old.id]
        logger.info("User -> '%s' restarts %s", user, ", ".join("{} {}".format(*item) for item in workloads))
        task = asyncio.get_running_loop().create_task(self._run(k8s, job))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job

    async def _restart(self, k8s: K8s, item: RestartItem, self_ref: tuple[str | None, str | None]) -> None:
        item.state = "restarting"
        try:
            skipped = await restart_workload(k8s, item.kind, item.name, self_ref)
        except Exception as error:
            if not isinstance(error, RestartError):
                logger.exception("Restart of %s %s failed", item.kind, item.name)
            item.state = "failed"
            item.message = str(error) or type(error).__name__
            return
        item.state = "skipped" if skipped else "done"
        item.message = skipped

    async def _run(self, k8s: K8s, job: RestartJob) -> None:
        self_ref = await anyio.to_thread.run_sync(self_workload, k8s)
        await asyncio.gather(*(self._restart(k8s, item, self_ref) for item in job.items))
        job.state = "failed" if any(item.state == "failed" for item in job.items) else "done"

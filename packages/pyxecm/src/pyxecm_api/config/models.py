"""Define models for the ConfigMaps, Secrets and workloads of the namespace."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# What the value of a key is - it tells how a value is best shown and edited.
KeyKind = Literal[
    "text",  # a single line
    "multiline",  # text with more lines
    "json",
    "yaml",
    "xml",
    "certificate",  # PEM: one or more certificates (a chain)
    "private-key",  # PEM: a private key
    "docker-config",  # .dockerconfigjson / .dockercfg of an image pull secret
    "binary",  # not UTF-8 text (keystores, archives) or binaryData of a ConfigMap
]

WorkloadKind = Literal["Deployment", "StatefulSet", "DaemonSet"]


class CertificateInfo(BaseModel):
    """What a certificate tells - without the certificate itself."""

    subject: str
    common_name: str | None
    issuer: str
    # The DNS names and IP addresses it is valid for.
    sans: list[str]
    not_before: datetime
    not_after: datetime
    serial: str
    fingerprint_sha256: str
    self_signed: bool
    is_ca: bool
    # "RSA 2048", "EC secp256r1", "Ed25519" ...
    key_type: str


class PrivateKeyInfo(BaseModel):
    """What a private key is - without the key itself."""

    # "RSA 2048", ... or "encrypted" for a key that needs a password.
    key_type: str
    # The key of the same object holding the certificate this private key belongs to.
    matches: str | None = None


class ConfigKey(BaseModel):
    """A key of a ConfigMap or Secret."""

    name: str
    # Size of the value in bytes.
    size: int
    kind: KeyKind
    # The certificates of a "certificate" key (the first one is the leaf of a chain).
    certificates: list[CertificateInfo] | None = None
    private_key: PrivateKeyInfo | None = None
    # ConfigMaps only - their values are not secret: the value as text, or base64 for a binary one.
    value: str | None = None
    value_base64: str | None = None


class ConfigUsage(BaseModel):
    """Something that uses a ConfigMap or Secret."""

    kind: Literal["Deployment", "StatefulSet", "DaemonSet", "Ingress"]
    name: str
    # How: "volume", "env", "image-pull" (pull secret), "tls" (certificate of an Ingress).
    via: list[str]
    # A workload whose pods read it - a restart applies a change. An Ingress picks it up itself.
    restartable: bool
    # The workload of the Customizer itself: restarting it ends this API for a while.
    is_self: bool = False


class ConfigObject(BaseModel):
    """A ConfigMap or Secret."""

    kind: Literal["ConfigMap", "Secret"]
    name: str
    # The type of a Secret (Opaque, kubernetes.io/tls, ...); None for a ConfigMap.
    type: str | None = None
    keys: list[ConfigKey]
    labels: dict[str, str]
    # "Helm", "cert-manager" ... when something else manages it and may overwrite changes.
    managed_by: str | None = None
    # The Helm release it belongs to.
    release: str | None = None
    created: datetime | None
    resource_version: str
    # It cannot be changed here, and why.
    read_only: bool = False
    read_only_reason: str | None = None
    used_by: list[ConfigUsage]


class ConfigList(BaseModel):
    """The ConfigMaps or Secrets of the namespace."""

    namespace: str
    items: list[ConfigObject]


class ConfigUpdate(BaseModel):
    """A change of a ConfigMap or Secret: keys to set and keys to delete."""

    # The version the change is based on: the object was not changed since (409 otherwise).
    resource_version: str
    # Text values.
    set: dict[str, str] = Field(default_factory=dict)
    # Binary values (base64).
    set_base64: dict[str, str] = Field(default_factory=dict)
    delete: list[str] = Field(default_factory=list)


class SecretValue(BaseModel):
    """The value of one key of a Secret."""

    name: str
    key: str
    value_base64: str
    # The value as text - None when it is not UTF-8 text.
    text: str | None


class CertificateInspectRequest(BaseModel):
    """PEM text to look at before it is saved."""

    certificate: str | None = None
    private_key: str | None = None


class CertificateInspection(BaseModel):
    """What a PEM text holds, and whether its private key belongs to its certificate."""

    certificates: list[CertificateInfo]
    private_key: PrivateKeyInfo | None = None
    # None when there is not both a certificate and a key to compare.
    key_matches: bool | None = None
    error: str | None = None


class Workload(BaseModel):
    """A workload of the namespace, with its rollout state."""

    kind: WorkloadKind
    name: str
    replicas: int
    ready: int
    updated: int
    # A rollout (a restart) is under way.
    rolling: bool
    # "RollingUpdate", "Recreate" or "OnDelete".
    strategy: str
    # A restart makes it unavailable for a while: a single pod, or replaced all at once.
    downtime_expected: bool
    restarted_at: str | None = None
    is_self: bool = False
    configmaps: list[str]
    secrets: list[str]


class WorkloadList(BaseModel):
    """The workloads of the namespace."""

    workloads: list[Workload]


class WorkloadRef(BaseModel):
    """A workload to restart."""

    kind: WorkloadKind
    name: str = Field(min_length=1, max_length=253)


class RestartRequest(BaseModel):
    """Workloads to restart, all at the same time."""

    workloads: list[WorkloadRef] = Field(min_length=1, max_length=50)


class RestartItem(BaseModel):
    """The restart of one workload."""

    kind: WorkloadKind
    name: str
    state: Literal["pending", "restarting", "done", "failed", "skipped"]
    message: str | None = None


class RestartJob(BaseModel):
    """Workloads restarted at the same time, each with a rolling restart."""

    id: str
    state: Literal["running", "done", "failed"]
    started: datetime
    items: list[RestartItem]

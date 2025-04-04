"""Kubernetes Module to implement functions to read / write Kubernetes objects.

This includes as Pods, Stateful Sets, Config Maps, ...

https://github.com/kubernetes-client/python
https://github.com/kubernetes-client/python/blob/master/kubernetes/README.md
https://github.com/kubernetes-client/python/tree/master/examples
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import time
from datetime import datetime, timezone

from kubernetes import client, config
from kubernetes.client import (
    AppsV1Api,
    CoreV1Api,
    NetworkingV1Api,
    V1ConfigMap,
    V1ConfigMapList,
    V1Ingress,
    V1Pod,
    V1PodList,
    V1Scale,
    V1Service,
    V1StatefulSet,
)
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException
from kubernetes.stream import stream

default_logger = logging.getLogger("pyxecm.customizer.k8s")


class K8s:
    """Provides an interface to interact with the Kubernetes API.

    This class can run both in-cluster and locally using kubeconfig.
    It offers methods to interact with Kubernetes namespaces, pods,
    and various API objects like CoreV1, AppsV1, and NetworkingV1.

    Attributes:
        logger (logging.Logger): Logger for the class.
        _core_v1_api (CoreV1Api): API client for Kubernetes Core V1.
        _apps_v1_api (AppsV1Api): API client for Kubernetes Apps V1.
        _networking_v1_api (NetworkingV1Api): API client for Kubernetes Networking V1.
        _namespace (str): The namespace in which operations are performed.

    """

    logger: logging.Logger = default_logger

    _core_v1_api = None
    _apps_v1_api = None
    _networking_v1_api = None
    _namespace = None

    def __init__(
        self,
        kubeconfig_file: str | None = None,
        namespace: str = "default",
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the Kubernetes object.

        Args:
            kubeconfig_file (str | None, optional):
                Path to a kubeconfig file. Defaults to None.
            namespace (str, optional):
                The Kubernetes name space. Defaults to "default".
            logger (logging.Logger, optional):
                The logger object. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("k8s")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        # Configure Kubernetes API authentication to use pod serviceAccount

        try:
            config.load_incluster_config()
            configured = True
        except ConfigException:
            configured = False
            self.logger.info("Failed to load in-cluster config")

        if kubeconfig_file is None:
            kubeconfig_file = os.getenv(
                "KUBECONFIG",
                os.path.expanduser("~/.kube/config"),
            )

        if not configured:
            try:
                config.load_kube_config(config_file=kubeconfig_file)
            except ConfigException:
                self.logger.info(
                    "Failed to load kubernetes config with file -> '%s'",
                    kubeconfig_file,
                )

        self._core_v1_api = CoreV1Api()
        self._apps_v1_api = AppsV1Api()
        self._networking_v1_api = NetworkingV1Api()

        if namespace == "default":
            # Read current namespace
            try:
                with open(
                    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
                    encoding="utf-8",
                ) as namespace_file:
                    self._namespace = namespace_file.read()
            except FileNotFoundError:
                self._namespace = namespace
        else:
            self._namespace = namespace

    # end method definition

    def get_core_v1_api(self) -> CoreV1Api:
        """Return Kubernetes Core V1 API object.

        Returns:
            object: Kubernetes API object

        """

        return self._core_v1_api

    # end method definition

    def get_apps_v1_api(self) -> AppsV1Api:
        """Return Kubernetes Apps V1 API object.

        Returns:
            object: Kubernetes API object

        """

        return self._apps_v1_api

    # end method definition

    def get_networking_v1_api(self) -> NetworkingV1Api:
        """Return Kubernetes Networking V1 API object.

        Returns:
            object: Kubernetes API object

        """

        return self._networking_v1_api

    # end method definition

    def get_namespace(self) -> str:
        """Return Kubernetes Namespace.

        Returns:
            str: Kubernetes namespace

        """

        return self._namespace

    # end method definition

    def get_pod(self, pod_name: str) -> V1Pod:
        """Get a pod in the configured namespace (the namespace is defined in the class constructor).

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md#read_namespaced_pod

        Args:
            pod_name (str):
                The name of the Kubernetes pod in the current namespace.

        Returns:
            V1Pod (object) or None if the call fails.
            - api_version='v1',
            - kind='Pod',
            - metadata=V1ObjectMeta(...),
            - spec=V1PodSpec(...),
            - status=V1PodStatus(...)

        """

        try:
            response = self.get_core_v1_api().read_namespaced_pod(
                name=pod_name,
                namespace=self.get_namespace(),
            )
        except ApiException as e:
            if e.status == 404:
                self.logger.info("Pod -> '%s' not found (may be deleted).", pod_name)
                return None
            else:
                self.logger.error("Failed to get Pod -> '%s'!", pod_name)
                return None  # Unexpected error, return None
        return response

    # end method definition

    def list_pods(
        self,
        field_selector: str = "",
        label_selector: str = "",
    ) -> V1PodList:
        """List all Kubernetes pods in a given namespace.

        The list can be further restricted by specifying a field or label selector.

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md#list_namespaced_pod

        Args:
            field_selector (str): filter result based on fields
            label_selector (str): filter result based on labels

        Returns:
            V1PodList (object) or None if the call fails
            Properties can be accessed with the "." notation (this is an object not a dict!):
            - api_version: The Kubernetes API version.
            - items: A list of V1Pod objects, each representing a pod. You can access the fields of a
                    V1Pod object using dot notation, for example, pod.metadata.name to access the name of the pod
            - kind: The Kubernetes object kind, which is always "PodList".
            - metadata: Additional metadata about the pod list, such as the resource version.
            See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1PodList.md

        """

        try:
            response = self.get_core_v1_api().list_namespaced_pod(
                field_selector=field_selector,
                label_selector=label_selector,
                namespace=self.get_namespace(),
            )
        except ApiException:
            self.logger.error(
                "Failed to list Pods with field_selector -> '%s' and label_selector -> '%s'",
                field_selector,
                label_selector,
            )
            return None

        return response

    # end method definition

    def wait_pod_condition(
        self,
        pod_name: str,
        condition_name: str,
        sleep_time: int = 30,
    ) -> None:
        """Wait for the pod to reach a defined condition (e.g. "Ready").

        Args:
            pod_name (str):
                The name of the Kubernetes pod in the current namespace.
            condition_name (str):
                The name of the condition, e.g. "Ready".
            sleep_time (int):
                The number of seconds to wait between repetitive status checks.

        Returns:
            True once the pod reaches the condition - otherwise wait forever.

        """

        ready = False
        while not ready:
            try:
                pod_status = self.get_core_v1_api().read_namespaced_pod_status(
                    pod_name,
                    self.get_namespace(),
                )

                # Check if the pod has reached the defined condition:
                for cond in pod_status.status.conditions:
                    if cond.type == condition_name and cond.status == "True":
                        self.logger.info(
                            "Pod -> '%s' is in state -> '%s'!",
                            pod_name,
                            condition_name,
                        )
                        ready = True
                        break
                else:
                    self.logger.info(
                        "Pod -> '%s' is not yet in state -> '%s'. Waiting...",
                        pod_name,
                        condition_name,
                    )
                    time.sleep(sleep_time)
                    continue

            except ApiException:
                self.logger.error(
                    "Failed to wait for pod -> '%s'",
                    pod_name,
                )

    # end method definition

    def exec_pod_command(
        self,
        pod_name: str,
        command: list,
        max_retry: int = 3,
        time_retry: int = 10,
        container: str | None = None,
    ) -> str:
        """Execute a command inside a Kubernetes Pod (similar to kubectl exec on command line).

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md#connect_get_namespaced_pod_exec

        Args:
            pod_name (str):
                The name of the Kubernetes pod in the current namespace.
            command (list):
                A list of command and its parameters, e.g. ["/bin/bash", "-c", "pwd"]
                The "-c" is required to make the shell executing the command.
            max_retry (int):
                The maximum number of attempts to execute the command.
            time_retry (int):
                Wait time in seconds between retries.
            container (str):
                The container name if the pod runs multiple containers inside.

        Returns:
            str:
                Response of the command or None if the call fails.

        """

        pod = self.get_pod(pod_name=pod_name)
        if not pod:
            self.logger.error("Pod -> '%s' does not exist", pod_name)

        self.logger.debug("Execute command -> %s in pod -> '%s'", command, pod_name)

        retry_counter = 1

        while retry_counter <= max_retry:
            try:
                response = stream(
                    self.get_core_v1_api().connect_get_namespaced_pod_exec,
                    pod_name,
                    self.get_namespace(),
                    command=command,
                    container=container,
                    stderr=True,
                    stdin=False,
                    stdout=True,
                    tty=False,
                )
            except ApiException as exc:
                self.logger.warning(
                    "Failed to execute command, retry (%s/%s) -> %s in pod -> '%s'; error -> %s",
                    retry_counter,
                    max_retry,
                    command,
                    pod_name,
                    str(exc),
                )
                retry_counter = retry_counter + 1
                exception = exc
                self.logger.debug(
                    "Wait %s seconds before next retry...",
                    str(time_retry),
                )
                time.sleep(time_retry)
                continue
            else:
                self.logger.debug(response)
                return response

        self.logger.error(
            "Failed to execute command with %s retries -> %s in pod -> '%s'; error -> %s",
            max_retry,
            command,
            pod_name,
            str(exception),
        )

        return None

    # end method definition

    # Some commands like the OTAC spawner need to run interactive - otherwise the command "hangs"
    def exec_pod_command_interactive(
        self,
        pod_name: str,
        commands: list,
        timeout: int = 30,
        write_stderr_to_error_log: bool = True,
    ) -> str:
        """Execute a command inside a Kubernetes pod (similar to kubectl exec on command line).

        Other than exec_pod_command() method above this is an interactive execution using
        stdin and reading the output from stdout and stderr. This is required for longer
        running commands. It is currently used for restarting the spawner of Archive Center.
        The output of the command is pushed into the logging.

        Args:
            pod_name (str):
                The name of the Kubernetes pod in the current namespace
            commands (list):
                A list of command and its parameters, e.g. ["/bin/bash", "/etc/init.d/spawner restart"]
                Here we should NOT have a "-c" parameter!
            timeout (int):
                Timeout duration that is waited for any response.
                Each time a resonse is found in stdout or stderr we wait another timeout duration
                to make sure we get the full output of the command.
            write_stderr_to_error_log (bool):
                Flag to control if output in stderr should be written to info or error log stream.
                Default is write to error log (True).

        Returns:
            str:
                Response of the command or None if the call fails.

        """

        pod = self.get_pod(pod_name=pod_name)
        if not pod:
            self.logger.error("Pod -> '%s' does not exist", pod_name)

        if not commands:
            self.logger.error("No commands to execute on Pod ->'%s'!", pod_name)
            return None

        # Get first command - this should be the shell:
        command = commands.pop(0)

        try:
            response = stream(
                self.get_core_v1_api().connect_get_namespaced_pod_exec,
                pod_name,
                self.get_namespace(),
                command=command,
                stderr=True,
                stdin=True,  # This is important!
                stdout=True,
                tty=False,
                _preload_content=False,  # This is important!
            )
        except ApiException:
            self.logger.error(
                "Failed to execute command -> %s in pod -> '%s'",
                command,
                pod_name,
            )
            return None

        while response.is_open():
            got_response = False
            response.update(timeout=timeout)
            if response.peek_stdout():
                self.logger.debug(response.read_stdout().replace("\n", " "))
                got_response = True
            if response.peek_stderr():
                if write_stderr_to_error_log:
                    self.logger.error(response.read_stderr().replace("\n", " "))
                else:
                    self.logger.debug(response.read_stderr().replace("\n", " "))
                got_response = True
            if commands:
                command = commands.pop(0)
                self.logger.debug(
                    "Execute command -> %s in pod -> '%s'",
                    command,
                    pod_name,
                )
                response.write_stdin(command + "\n")
            # We continue as long as we get some response during timeout period
            elif not got_response:
                break

        response.close()

        return response

    # end method definition

    def delete_pod(self, pod_name: str) -> None:
        """Delete a pod in the configured namespace (the namespace is defined in the class constructor).

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md#delete_namespaced_pod

        Args:
            pod_name (str):
                The name of the Kubernetes pod in the current namespace.

        Returns:
            V1Status (object) or None if the call fails.
            - api_version: The Kubernetes API version.
            - kind: The Kubernetes object kind, which is always "Status".
            - metadata: Additional metadata about the status object, such as the resource version.
            - status: The status of the operation, which is either "Success" or an error status.
            - message: A human-readable message explaining the status.
            - reason: A short string that describes the reason for the status.
            - code: An HTTP status code that corresponds to the status.
            See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1Status.md

        """

        pod = self.get_pod(pod_name=pod_name)
        if not pod:
            self.logger.error("Pod -> '%s' does not exist!", pod_name)

        try:
            response = self.get_core_v1_api().delete_namespaced_pod(
                pod_name,
                namespace=self.get_namespace(),
            )
        except ApiException:
            self.logger.error(
                "Failed to delete Pod -> '%s'",
                pod_name,
            )
            return None

        return response

    # end method definition

    def get_config_map(self, config_map_name: str) -> V1ConfigMap:
        """Get a config map in the configured namespace (the namespace is defined in the class constructor).

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md#read_namespaced_config_map

        Args:
            config_map_name (str):
                The name of the Kubernetes config map in the current namespace.

        Returns:
            V1ConfigMap (object):
                Kubernetes Config Map object that includes these fields:
                - api_version:
                    The Kubernetes API version.
                - metadata:
                    A V1ObjectMeta object representing metadata about the V1ConfigMap object,
                    such as its name, labels, and annotations.
                - data:
                    A dictionary containing the non-binary data stored in the ConfigMap,
                    where the keys represent the keys of the data items and the values represent
                    the values of the data items.
                - binary_data:
                    A dictionary containing the binary data stored in the ConfigMap,
                    where the keys represent the keys of the binary data items and the values
                    represent the values of the binary data items. Binary data is encoded as base64
                    strings in the dictionary values.

        """

        try:
            response = self.get_core_v1_api().read_namespaced_config_map(
                name=config_map_name,
                namespace=self.get_namespace(),
            )
        except ApiException:
            self.logger.error(
                "Failed to get Config Map -> '%s'",
                config_map_name,
            )
            return None

        return response

    # end method definition

    def list_config_maps(
        self,
        field_selector: str = "",
        label_selector: str = "",
    ) -> V1ConfigMapList:
        """List all Kubernetes Config Maps in the current namespace.

        The list can be filtered by providing field selectors and label selectors.
        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md#list_namespaced_config_map

        Args:
            field_selector (str):
                To filter the result based on fields.
            label_selector (str):
                To filter result based on labels.

        Returns:
            V1ConfigMapList (object) or None if the call fails
            Properties can be accessed with the "." notation (this is an object not a dict!):
            - api_version: The Kubernetes API version.
            - items: A list of V1ConfigMap objects, each representing a config map. You can access the fields of a
                     V1Pod object using dot notation, for example, cm.metadata.name to access the name of the config map
            - kind: The Kubernetes object kind, which is always "ConfigMapList".
            - metadata: Additional metadata about the config map list, such as the resource version.
            See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1ConfigMapList.md

        """

        try:
            response = self.get_core_v1_api().list_namespaced_config_map(
                field_selector=field_selector,
                label_selector=label_selector,
                namespace=self.get_namespace(),
            )
        except ApiException:
            self.logger.error(
                "Failed to list Config Maps with field_selector -> '%s' and label_selector -> '%s'",
                field_selector,
                label_selector,
            )
            return None

        return response

    # end method definition

    def find_config_map(self, config_map_name: str) -> V1ConfigMapList:
        """Find a Kubernetes Config Map based on its name.

        This is just a wrapper method for list_config_maps()
        that uses the name as a field selector.

        Args:
            config_map_name (str):
                The name of the Kubernetes Config Map to search for.

        Returns:
            object:
                V1ConfigMapList (object) or None if the call fails.

        """

        try:
            response = self.list_config_maps(
                field_selector="metadata.name={}".format(config_map_name),
            )
        except ApiException:
            self.logger.error(
                "Failed to find Config Map -> '%s'",
                config_map_name,
            )
            return None

        return response

    # end method definition

    def replace_config_map(
        self,
        config_map_name: str,
        config_map_data: dict,
    ) -> V1ConfigMap:
        """Replace a Config Map with a new specification.

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md#replace_namespaced_config_map

        Args:
            config_map_name (str):
                The name of the Kubernetes Config Map to replace.
            config_map_data (dict):
                The updated specification of the Config Map.

        Returns:
            V1ConfigMap (object):
                Updated Kubernetes Config Map object or None if the call fails.
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1ConfigMap.md

        """

        try:
            response = self.get_core_v1_api().replace_namespaced_config_map(
                name=config_map_name,
                namespace=self.get_namespace(),
                body=client.V1ConfigMap(
                    metadata=client.V1ObjectMeta(
                        name=config_map_name,
                    ),
                    data=config_map_data,
                ),
            )
        except ApiException:
            self.logger.error(
                "Failed to replace Config Map -> '%s'",
                config_map_name,
            )
            return None

        return response

    # end method definition

    def get_stateful_set(self, sts_name: str) -> V1StatefulSet:
        """Get a Kubernetes Stateful Set based on its name.

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/AppsV1Api.md#read_namespaced_stateful_set

        Args:
            sts_name (str):
                The name of the Kubernetes stateful set

        Returns:
            V1StatefulSet (object):
                Kubernetes Stateful Set object or None if the call fails.
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1StatefulSet.md

        """

        try:
            response = self.get_apps_v1_api().read_namespaced_stateful_set(
                name=sts_name,
                namespace=self.get_namespace(),
            )
        except ApiException:
            self.logger.error(
                "Failed to get Stateful Set -> '%s'",
                sts_name,
            )
            return None

        return response

    # end method definition

    def get_stateful_set_scale(self, sts_name: str) -> V1Scale:
        """Get the number of replicas for a Kubernetes Stateful Set.

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/AppsV1Api.md#read_namespaced_stateful_set_scale

        Args:
            sts_name (str):
                The name of the Kubernetes Stateful Set.

        Returns:
            V1Scale (object):
                Kubernetes Scale object or None if the call fails.
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1Scale.md

        """

        try:
            response = self.get_apps_v1_api().read_namespaced_stateful_set_scale(
                name=sts_name,
                namespace=self.get_namespace(),
            )
        except ApiException:
            self.logger.error(
                "Failed to get scaling (replicas) of Stateful Set -> '%s'",
                sts_name,
            )
            return None

        return response

    # end method definition

    def patch_stateful_set(self, sts_name: str, sts_body: dict) -> V1StatefulSet:
        """Patch a Stateful set with new values.

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/AppsV1Api.md#patch_namespaced_stateful_set

        Args:
            sts_name (str):
                The name of the Kubernetes stateful set in the current namespace.
            sts_body (str):
                The patch string.

        Returns:
            V1StatefulSet (object):
                The patched Kubernetes Stateful Set object or None if the call fails.
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1StatefulSet.md

        """

        try:
            response = self.get_apps_v1_api().patch_namespaced_stateful_set(
                name=sts_name,
                namespace=self.get_namespace(),
                body=sts_body,
            )
        except ApiException:
            self.logger.error(
                "Failed to patch Stateful Set -> '%s' with -> %s",
                sts_name,
                sts_body,
            )
            return None

        return response

    # end method definition

    def scale_stateful_set(self, sts_name: str, scale: int) -> V1StatefulSet:
        """Scale a stateful set to a specific number of replicas.

        It uses the class method patch_stateful_set() above.

        Args:
            sts_name (str):
                The name of the Kubernetes stateful set in the current namespace.
            scale (int):
                The number of replicas (pods) the stateful set shall be scaled to.

        Returns:
            V1StatefulSet (object):
                Kubernetes Stateful Set object or None if the call fails.
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1StatefulSet.md

        """

        try:
            response = self.patch_stateful_set(
                sts_name,
                sts_body={"spec": {"replicas": scale}},
            )
        except ApiException:
            self.logger.error(
                "Failed to scale Stateful Set -> '%s' to -> %s replicas",
                sts_name,
                scale,
            )
            return None

        return response

    # end method definition

    def get_service(self, service_name: str) -> V1Service:
        """Get a Kubernetes Service with a defined name in the current namespace.

        Args:
            service_name (str):
                The name of the Kubernetes Service in the current namespace.

        Returns:
            V1Service (object):
                Kubernetes Service object or None if the call fails
                This is NOT a dict but an object - the you have to use the "." syntax to access to returned elements.
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1Service.md

        """

        try:
            response = self.get_core_v1_api().read_namespaced_service(
                name=service_name,
                namespace=self.get_namespace(),
            )
        except ApiException:
            self.logger.error(
                "Failed to get Service -> '%s'",
                service_name,
            )
            return None

        return response

    # end method definition

    def list_services(self, field_selector: str = "", label_selector: str = "") -> None:
        """List all Kubernetes Service in the current namespace.

        The list can be filtered by providing field selectors and label selectors.
        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md#list_namespaced_service

        Args:
            field_selector (str):
                To filter result based on fields.
            label_selector (str):
                To filter result based on labels.

        Returns:
            V1ServiceList (object):
                A list of Kubernetes Services or None if the call fails.
                Properties can be accessed with the "." notation (this is an object not a dict!):
                - api_version: The Kubernetes API version.
                - items: A list of V1Service objects, each representing a service.
                        You can access the fields of a V1Service object using dot notation,
                        for example, service.metadata.name to access the name of the service
                - kind: The Kubernetes object kind, which is always "ServiceList".
                - metadata: Additional metadata about the pod list, such as the resource version.
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1ServiceList.md

        """

        try:
            response = self.get_core_v1_api().list_namespaced_service(
                field_selector=field_selector,
                label_selector=label_selector,
                namespace=self.get_namespace(),
            )
        except ApiException:
            self.logger.error(
                "Failed to list Services with field_selector -> '%s' and label_selector -> '%s'",
                field_selector,
                label_selector,
            )
            return None

        return response

    # end method definition

    def patch_service(self, service_name: str, service_body: dict) -> V1Service:
        """Patch a Kubernetes Service with an updated spec.

        Args:
            service_name (str):
                The name of the Kubernetes Ingress in the current namespace.
            service_body (dict):
                The new / updated Service body spec.
                (will be merged with existing values)

        Returns:
            V1Service (object):
                The patched Kubernetes Service or None if the call fails.
                This is NOT a dict but an object - you have to use the "." syntax
                to access to returned elements
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1Service.md

        """

        try:
            response = self.get_core_v1_api().patch_namespaced_service(
                name=service_name,
                namespace=self.get_namespace(),
                body=service_body,
            )
        except ApiException:
            self.logger.error(
                "Failed to patch Service -> '%s' with -> %s",
                service_name,
                service_body,
            )
            return None

        return response

    # end method definition

    def get_ingress(self, ingress_name: str) -> V1Ingress:
        """Get a Kubernetes Ingress with a defined name in the current namespace.

        Args:
            ingress_name (str):
                The name of the Kubernetes Ingress in the current namespace.

        Returns:
            V1Ingress (object):
                Kubernetes Ingress or None if the call fails
                This is NOT a dict but an object - the you have to use the "." syntax to access to returned elements.
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1Ingress.md

        """

        try:
            response = self.get_networking_v1_api().read_namespaced_ingress(
                name=ingress_name,
                namespace=self.get_namespace(),
            )
        except ApiException:
            self.logger.error(
                "Failed to get Ingress -> '%s'!",
                ingress_name,
            )
            return None

        return response

    # end method definition

    def patch_ingress(self, ingress_name: str, ingress_body: dict) -> V1Ingress:
        """Patch a Kubernetes Ingress with a updated spec.

        See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/NetworkingV1Api.md#patch_namespaced_ingress

        Args:
            ingress_name (str):
                The name of the Kubernetes Ingress in the current namespace.
            ingress_body (dict):
                The new / updated ingress body spec.
                (will be merged with existing values)

        Returns:
            V1Ingress (object):
                The patched Kubernetes Ingress object or None if the call fails
                This is NOT a dict but an object - you have to use the
                "." syntax to access to returned elements
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1Ingress.md

        """

        try:
            response = self.get_networking_v1_api().patch_namespaced_ingress(
                name=ingress_name,
                namespace=self.get_namespace(),
                body=ingress_body,
            )
        except ApiException:
            self.logger.error(
                "Failed to patch Ingress -> '%s' with -> %s",
                ingress_name,
                ingress_body,
            )
            return None

        return response

    # end method definition

    def update_ingress_backend_services(
        self,
        ingress_name: str,
        hostname: str,
        service_name: str,
        service_port: int,
    ) -> V1Ingress:
        """Update a backend service and port of an Kubernetes Ingress.

        "spec": {
            "rules": [
                {
                    "host": host,
                    "http": {
                        "paths": [
                            {
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": <service_name>,
                                        "port": {
                                            "name": None,
                                            "number": <service_port>,
                                        },
                                    },
                                },
                            }
                        ]
                    },
                }
            ]
        }

        Args:
            ingress_name (str):
                The name of the Kubernetes Ingress in the current namespace.
            hostname (str):
                The hostname that should get an updated backend service / port.
            service_name (str):
                The new backend service name.
            service_port (int):
                The new backend service port.

        Returns:
            V1Ingress (object):
                The updated Kubernetes Ingress object or None if the call fails.
                This is NOT a dict but an object - you have to use the "." syntax
                to access to returned elements
                See: https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1Ingress.md

        """

        ingress = self.get_ingress(ingress_name=ingress_name)
        if not ingress:
            return None

        host = ""
        rules = ingress.spec.rules
        rule_index = 0
        for rule in rules:
            if hostname in rule.host:
                host = rule.host
                path = rule.http.paths[0]
                backend = path.backend
                service = backend.service

                self.logger.debug(
                    "Replace backend service -> '%s' (%s) with new backend service -> '%s' (%s)",
                    service.name,
                    service.port.number,
                    service_name,
                    service_port,
                )

                service.name = service_name
                service.port.number = service_port
                break
            rule_index += 1

        if not host:
            self.logger.error("Cannot find host.")
            return None

        body = [
            {
                "op": "replace",
                "path": "/spec/rules/{}/http/paths/0/backend/service/name".format(
                    rule_index,
                ),
                "value": service_name,
            },
            {
                "op": "replace",
                "path": "/spec/rules/{}/http/paths/0/backend/service/port/number".format(
                    rule_index,
                ),
                "value": service_port,
            },
        ]

        return self.patch_ingress(ingress_name, body)

    # end method definition

    def verify_pod_status(
        self,
        pod_name: str,
        timeout: int = 1800,
        total_containers: int = 1,
        ready_containers: int = 1,
        retry_interval: int = 30,
    ) -> bool:
        """Verify if a pod is in a 'Ready' state by checking the status of its containers.

        This function waits for a Kubernetes pod to reach the 'Ready' state, where a specified number
        of containers are ready. It checks the pod status at regular intervals and reports the status
        using logs. If the pod does not reach the 'Ready' state within the specified timeout,
        it returns `False`.

        Args:
            pod_name (str):
                The name of the pod to check the status for.
            timeout (int, optional):
                The maximum time (in seconds) to wait for the pod to become ready. Defaults to 1800.
            total_containers (int, optional):
                The total number of containers expected to be running in the pod. Defaults to 1.
            ready_containers (int, optional):
                The minimum number of containers that need to be in a ready state. Defaults to 1.
            retry_interval (int, optional):
                Time interval (in seconds) between each retry to check pod readiness. Defaults to 30.

        Returns:
            bool:
                Returns `True` if the pod reaches the 'Ready' state with the specified number of containers ready
                within the timeout. Otherwise, returns `False`.

        """

        def wait_for_pod_ready(pod_name: str, timeout: int) -> bool:
            """Wait until the pod is in the 'Ready' state with the specified number of containers ready.

            This sub method repeatedly checks the readiness of the pod, logging the
            status of the containers. If the pod does not exist, it retries after waiting
            and logs detailed information at each step.

            Args:
                pod_name (str):
                    The name of the pod to check the status for.
                timeout (int):
                    The maximum time (in seconds) to wait for the pod to become ready.

            Returns:
                bool:
                    Returns `True` if the pod is ready with the specified number of containers in a 'Ready' state.
                    Otherwise, returns `False`.

            """

            elapsed_time = 0  # Initialize elapsed time

            while elapsed_time < timeout:
                pod = self.get_pod(pod_name=pod_name)

                if not pod:
                    self.logger.warning(
                        "Pod -> '%s' does not exist, waiting 300 seconds to retry.",
                        pod_name,
                    )
                    time.sleep(300)
                    pod = self.get_pod(pod_name=pod_name)

                if not pod:
                    self.logger.error(
                        "Pod -> '%s' still does not exist after retry!",
                        pod_name,
                    )
                    return False

                # Get the ready status of containers
                container_statuses = pod.status.container_statuses
                if container_statuses and all(container.ready for container in container_statuses):
                    current_ready_containers = sum(1 for c in container_statuses if c.ready)
                    total_containers_in_pod = len(container_statuses)

                    if current_ready_containers >= ready_containers and total_containers_in_pod == total_containers:
                        self.logger.info(
                            "Pod -> '%s' is ready with %d/%d containers.",
                            pod_name,
                            current_ready_containers,
                            total_containers_in_pod,
                        )
                        return True
                    else:
                        self.logger.debug(
                            "Pod -> '%s' is not yet ready (%d/%d).",
                            pod_name,
                            current_ready_containers,
                            total_containers_in_pod,
                        )
                else:
                    self.logger.debug("Pod -> '%s' is not yet ready.", pod_name)

                self.logger.info(
                    "Waiting %s seconds before next pod status check.",
                    retry_interval,
                )
                time.sleep(
                    retry_interval,
                )  # Sleep for the retry interval before checking again
                elapsed_time += retry_interval

            self.logger.error(
                "Pod -> '%s' is not ready after %d seconds.",
                pod_name,
                timeout,
            )
            return False

        # end method definition

        # Wait until the pod is ready
        return wait_for_pod_ready(pod_name=pod_name, timeout=timeout)

    # end method definition

    def verify_pod_deleted(
        self,
        pod_name: str,
        timeout: int = 300,
        retry_interval: int = 30,
    ) -> bool:
        """Verify if a pod is deleted within the specified timeout.

        Args:
            pod_name (str):
                The name of the pod to check.
            timeout (int):
                Maximum time to wait for the pod to be deleted (in seconds).
            retry_interval:
                Time interval between retries (in seconds).

        Returns:
            bool:
                True if the pod is deleted, False otherwise.

        """

        elapsed_time = 0  # Initialize elapsed time

        while elapsed_time < timeout:
            pod = self.get_pod(pod_name=pod_name)

            if not pod:
                self.logger.info("Pod -> '%s' has been deleted successfully.", pod_name)
                return True

            self.logger.debug(
                "Pod -> '%s' still exists. Waiting %s seconds before next check.",
                pod_name,
                retry_interval,
            )
            time.sleep(retry_interval)
            elapsed_time += retry_interval

        self.logger.error("Pod -> '%s' was not deleted within %d seconds.", pod_name, timeout)

        return False

    # end method definition

    def restart_deployment(self, deployment_name: str) -> bool:
        """Restart a Kubernetes deployment using rolling restart.

        Args:
            deployment_name (str):
                Name of the Kubernetes deployment.

        Returns:
            bool:
                True if successful, False otherwise.

        """

        now = datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z"

        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": now,
                        },
                    },
                },
            },
        }
        try:
            self.get_apps_v1_api().patch_namespaced_deployment(
                deployment_name,
                self.get_namespace(),
                body,
                pretty="true",
            )

        except ApiException:
            self.logger.exception(
                "Failed to restart deployment -> '%s'!",
                deployment_name,
            )
            return False

        else:
            return True

    # end method definition

    def restart_stateful_set(self, sts_name: str) -> bool:
        """Restart a Kubernetes stateful set using rolling restart.

        Args:
            sts_name (str):
                Name of the Kubernetes statefulset.

        Returns:
            bool:
                True if successful, False otherwise.

        """

        now = datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z"

        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": now,
                        },
                    },
                },
            },
        }
        try:
            self.get_apps_v1_api().patch_namespaced_stateful_set(sts_name, self.get_namespace(), body, pretty="true")

        except ApiException:
            self.logger.exception(
                "Failed to restart stateful set -> '%s'!",
                sts_name,
            )
            return False

        else:
            return True

    # end method definition

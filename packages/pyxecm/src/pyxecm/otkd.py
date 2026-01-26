"""OTKD Module to implement functions to communicate with Knowledge Discovery (Nifi).

Nifi API documentation: https://nifi.apache.org/nifi-docs/rest-api.html

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import platform
import sys
import time
from http import HTTPStatus
from importlib.metadata import version

import requests

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otkd"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

REQUEST_FORM_HEADERS = {
    "User-Agent": USER_AGENT,
    "Content-Type": "application/x-www-form-urlencoded",
}

REQUEST_JSON_HEADERS = {
    "User-Agent": USER_AGENT,
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/json",
}

REQUEST_UPLOAD_HEADERS = {
    "User-Agent": USER_AGENT,
    # DO NOT set "Content-Type" manually
}

REQUEST_TIMEOUT = 60.0
REQUEST_RETRY_DELAY = 20.0
REQUEST_MAX_RETRIES = 2

default_logger = logging.getLogger(MODULE_NAME)


class OTKD:
    """Class OTKD is used to communicate Knowledge Discovery via REST API."""

    # Only class variables or class-wide constants should be defined here:

    logger: logging.Logger = default_logger

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        username: str,
        password: str,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the OTKD object.

        Args:
            protocol (str):
                Either http or https.
            hostname (str):
                The hostname of the Knowledge Discovery  to communicate with.
            port (int):
                The port number used to talk to the Knowledge Discovery .
            username (str):
                The admin user name of Knowledge Discovery.
            password (str):
                The admin password of Knowledge Discovery.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otkd")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        otkd_config = {}

        otkd_config["hostname"] = hostname or ""
        otkd_config["protocol"] = protocol or "http"

        if port:
            otkd_config["port"] = port
        else:
            otkd_config["port"] = 80

        otkd_config["username"] = username or "admin"
        otkd_config["password"] = password or ""
        if not otkd_config["password"]:
            self.logger.warning("Missing password for user -> '%s'.", otkd_config["username"])

        otkd_base_url = protocol + "://" + otkd_config["hostname"]
        if str(port) not in ["80", "443"]:
            otkd_base_url += ":{}".format(port)
        otkd_config["baseUrl"] = otkd_base_url
        otkd_config["restUrl"] = otkd_config["baseUrl"] + "/nifi-api"
        otkd_config["flowUrl"] = otkd_config["restUrl"] + "/flow"
        otkd_config["authenticationUrl"] = otkd_config["restUrl"] + "/access/token"

        self._config = otkd_config
        self._otkd_token = None

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict: Configuration dictionary

        """
        return self._config

    # end method definition

    def hostname(self) -> str:
        """Return the Knowledge Discovery hostname.

        Returns:
            str: Knowledge Discovery hostname

        """
        return self.config()["hostname"]

    # end method definition

    def set_hostname(self, hostname: str) -> None:
        """Set the Knowledge Discovery hostname.

        Args:
            hostname (str):
                The new Knowledge Discovery hostname.

        """
        self.config()["hostname"] = hostname

    # end method definition

    def credentials(self, basic_auth: bool = False) -> dict:
        """Get credentials (username + password).

        Returns:
            dict:
                A dictionary with username and password.

        """

        if basic_auth:
            return (self.config()["username"], self.config()["password"])

        return {
            "username": self.config()["username"],
            "password": self.config()["password"],
        }

    # end method definition

    def set_credentials(
        self,
        username: str = "",
        password: str = "",
    ) -> None:
        """Set the credentials for Knowledge Discovery.

        Args:
            username (str, optional):
                A non-default user name of the "admin" user. Defaults to "".
            password (str, optional):
                Password of the "admin" user. Defaults to "".

        """

        self.config()["username"] = username or "admin"
        self.config()["password"] = password or ""

    # end method definition

    def base_url(self) -> str:
        """Return the Knowledge Discovery base URL.

        Returns:
            str: Knowledge Discovery base URL

        """

        return self.config()["baseUrl"]

    # end method definition

    def rest_url(self) -> str:
        """Return the Knowledge Discovery REST URL.

        Returns:
            str:
                Knowledge Discovery REST URL

        """

        return self.config()["restUrl"]

    # end method definition

    def request_form_header(self) -> dict:
        """Deliver the FORM request header used for the SOAP calls.

        Consists of Token + Form Headers (see global variable)

        Args:
            None.

        Return:
            dict:
                The request header for forms content type that includes the authorization token.

        """

        request_header = {}
        request_header.update(REQUEST_FORM_HEADERS)
        if self._otkd_token:
            request_header.update({"Authorization": "Bearer {}".format(self._otkd_token)})

        return request_header

    # end method definition

    def request_json_header(self) -> dict:
        """Deliver the JSON request header used for the CRUD REST API calls.

        Consists of JSON Headers (see global variable) and optional Authorization bearer token.

        Args:
            None.

        Return:
            dict:
                The request header for JSON content type that optionally includes the authorization token.

        """

        request_header = {}
        request_header.update(REQUEST_JSON_HEADERS)
        if self._otkd_token:
            request_header.update({"Authorization": "Bearer {}".format(self._otkd_token)})

        return request_header

    # end method definition

    def request_upload_header(self) -> dict:
        """Deliver the upload request header used for the upload REST API calls that uses the 'file' parameter.

        Consists of only the 'User-Agent' Header (see global variable) and optional Authorization bearer token.
        For uploads it is IMPORTANT to NOT set the 'Content-Type' header.

        Args:
            None.

        Return:
            dict:
                The request header without the 'Content-Type' that only includes
                the 'User-Agent' header and optionally the authorization token.

        """

        request_header = {}
        request_header.update(REQUEST_UPLOAD_HEADERS)
        if self._otkd_token:
            request_header.update({"Authorization": "Bearer {}".format(self._otkd_token)})

        return request_header

    # end method definition

    def do_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        data: dict | None = None,
        json_data: dict | None = None,
        files: dict | None = None,
        timeout: float | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        show_warning: bool = False,
        warning_message: str = "",
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        retry_forever: bool = False,
        parse_request_response: bool = True,
    ) -> dict | None:
        """Call an Nifi REST API in a safe way.

        Args:
            url (str):
                The URL to send the request to.
            method (str, optional):
                The HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional):
                The request headers. Defaults to None.
            data (dict | None, optional):
                Request payload. Defaults to None
            json_data (dict | None, optional):
                Request payload for the JSON parameter. Defaults to None.
            files (dict | None, optional):
                Dictionary of {"name": file-tuple} for multipart encoding upload.
                File-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            timeout (float | None, optional):
                The timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed REST call.
                If False, then only a warning is logged. Defaults to True.
            show_warning (bool, optional):
                Whether or not an warning should be logged in case of a
                failed REST call.
                If False, then only a warning is logged. Defaults to True.
            warning_message (str, optional):
                Specific warning message. Defaults to "". If not given the error_message will be used.
            failure_message (str, optional):
                Specific error message. Defaults to "".
            success_message (str, optional):
                Specific success message. Defaults to "".
            max_retries (int, optional):
                How many retries on Connection errors? Default is REQUEST_MAX_RETRIES.
            retry_forever (bool, optional):
                Eventually wait forever - without timeout. Defaults to False.
            parse_request_response (bool, optional):
                Defines if the response.text should be interpreted as json and loaded into a dictionary.
                True is the default.

        Returns:
            dict | None:
                Response of OTDS REST API or None in case of an error.

        """

        # In case of an expired session we reauthenticate and
        # try 1 more time. Session expiration should not happen
        # twice in a row:
        retries = 0

        while True:
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    data=data,
                    json=json_data,
                    files=files,
                    headers=headers,
                    auth=(self.credentials(basic_auth=True)),
                    timeout=timeout,
                )

                if response.ok:
                    if success_message:
                        self.logger.info(success_message)
                    if parse_request_response:
                        return self.parse_request_response(response)
                    else:
                        return response
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    self.logger.info("Session has expired - try to re-authenticate...")
                    self.authenticate(revalidate=True)
                    retries += 1
                else:
                    if show_error:
                        self.logger.error(
                            "%s; status -> %s/%s; error -> %s",
                            failure_message,
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
                            response.text,
                        )
                    elif show_warning:
                        self.logger.warning(
                            "%s; status -> %s/%s; warning -> %s",
                            warning_message if warning_message else failure_message,
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
                            response.text,
                        )
                    return None
            except requests.exceptions.Timeout:
                if retries <= max_retries:
                    self.logger.warning(
                        "Request timed out. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    self.logger.error(
                        "%s; timeout error.",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                        self.logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                    else:
                        return None
            except requests.exceptions.ConnectionError:
                if retries <= max_retries:
                    self.logger.warning(
                        "Connection error. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    self.logger.error(
                        "%s; connection error.",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                        self.logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                        time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                    else:
                        return None
            # end try
            self.logger.warning(
                "Retrying Nifi REST API %s call -> %s... (retry = %s)",
                method,
                url,
                str(retries),
            )
        # end while True

    # end method definition

    def parse_request_response(
        self,
        response_object: object,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Convert the text property of a request response object to a dictionary.

        This is done in a safe way that also handles exceptions.

        Args:
            response_object (object):
                The reponse object delivered by the request call.
            additional_error_message (str):
                To print a custom error message.
            show_error (bool):
                If True, log an error, if False log a warning.

        Returns:
            dict:
                The response or None in case of an error.

        """

        if not response_object:
            return None

        try:
            dict_object = json.loads(response_object.text)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSon. {}; error -> {}".format(
                    additional_error_message,
                    exception,
                )
            else:
                message = "Cannot decode response as JSon; error -> {}".format(
                    exception,
                )
            if show_error:
                self.logger.error(message)
            else:
                self.logger.debug(message)
            return None
        else:
            return dict_object

    # end method definition

    def authenticate(self, revalidate: bool = False) -> str | None:
        """Authenticate at Knowledge Discovery and retrieve Ticket.

        Args:
            revalidate (bool, optional):
                Determins if a re-athentication is enforced
                (e.g. if session has timed out with 401 error).
                By default we use the OTDS ticket (if exists) for the authentication with OTCS.
                This switch allows the forced usage of username / password for the authentication.

        Returns:
            str | None:
                Token information of None in case of an error.
                Also stores cookie information in self._cookie

        """

        # Already authenticated and session still valid?
        if self._otkd_token and not revalidate:
            self.logger.debug(
                "Session still valid - return existing ticket -> %s",
                str(self._otkd_token),
            )
            return self._otkd_token

        request_url = self.config()["authenticationUrl"]

        # Check if previous authentication was not successful.
        # Then we do the normal username + password authentication:
        self.logger.debug(
            "Requesting OTKD ticket with username and password; calling -> %s",
            request_url,
        )

        response = None
        try:
            response = requests.post(
                url=request_url,
                data=self.credentials(),
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exception:
            self.logger.warning(
                "Unable to connect to -> %s; error -> %s",
                request_url,
                str(exception),
            )
            self.logger.warning("Nifi service may not be ready yet.")
            return None

        if response.ok:
            token = response.text.strip()
            self.logger.debug("NiFi access token -> %s", token)
            self._otkd_token = token
            return token
        else:
            self.logger.error(
                "Failed to request an Nifi access token; status -> %s, error -> %s",
                response.status_code,
                response.text,
            )
            return None

    # end method definition

    def get_root_process_group(self) -> dict | None:
        """Get the root process group in Nifi.

        Returns:
            dict | None:
                The root process group. None in case of an error.

        """

        request_url = self.config()["restUrl"] + "/process-groups/root"
        request_header = self.request_json_header()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Failed to get root process group",
        )

    # end method definition

    def get_process_groups(self, parent_process_group_id: str) -> list | None:
        """Get the (root) process groups.

        Args:
            parent_process_group_id (str):
                The parent of the process groups to retrieve.

        Returns:
            list | None:
                The list of process groups. None in case an error has occured.

        Example:
        [
            {
                'revision': {
                    'clientId': 'none',
                    'version': 2
                },
                'id': '17c9d355-0197-1000-ffff-fffff3783d78',
                'uri': 'https://nifi.master.terrarium.cloud:443/nifi-api/process-groups/17c9d355-0197-1000-ffff-fffff3783d78',
                'position': {
                    'x': 0.0,
                    'y': 0.0
                },
                'permissions': {
                    'canRead': True,
                    'canWrite': True
                },
                'bulletins': [],
                'component': {
                    'id': '17c9d355-0197-1000-ffff-fffff3783d78',
                    'parentGroupId': '1783526b-0197-1000-24bf-df0e446b7f0e',
                    'position': {...},
                    'name': 'KD_Demo_Integration',
                    'comments': '',
                    'parameterContext': {...},
                    'flowfileConcurrency': 'UNBOUNDED',
                    'flowfileOutboundPolicy': 'STREAM_WHEN_AVAILABLE',
                    'defaultFlowFileExpiration': '0 sec',
                    'defaultBackPressureObjectThreshold': 10000,
                    'defaultBackPressureDataSizeThreshold': '1 GB',
                    'logFileSuffix': '',
                    'executionEngine': 'INHERITED',
                    'maxConcurrentTasks': 1,
                    'statelessFlowTimeout': '1 min',
                    'runningCount': 34,
                    'stoppedCount': 0,
                    'invalidCount': 35,
                    'disabledCount': 3,
                    ...
                },
                'status': {
                    'id': '17c9d355-0197-1000-ffff-fffff3783d78',
                    'name': 'KD_Demo_Integration',
                    'statsLastRefreshed': '17:05:34 GMT',
                    'aggregateSnapshot': {...}
                },
                'runningCount': 34,
                'stoppedCount': 0,
                'invalidCount': 35,
                'disabledCount': 3,
                'activeRemotePortCount': 0,
                'inactiveRemotePortCount': 0,
                'upToDateCount': 0,
                'locallyModifiedCount': 0,
                'staleCount': 0,
                'locallyModifiedAndStaleCount': 0,
                'syncFailureCount': 0,
                'localInputPortCount': 0,
                'localOutputPortCount': 0,
                'publicInputPortCount': 0,
                'publicOutputPortCount': 0,
                'parameterContext': {
                    'id': 'efc9e58c-946a-3125-a52e-c395a6be2990',
                    'permissions': {...},
                    'component': {...}
                },
                inputPortCount': 0,
                'outputPortCount': 0
            }
        ]

        """

        request_url = self.config()["restUrl"] + "/process-groups/" + parent_process_group_id + "/process-groups"
        request_header = self.request_json_header()

        process_groups = self.do_request(
            url=request_url, method="GET", headers=request_header, failure_message="Failed to get process groups"
        )

        if not process_groups:
            return None

        return process_groups.get("processGroups")

    # end method definition

    def get_process_group_by_parent_and_name(self, name: str, parent_id: str | None = None) -> dict | None:
        """Get a process group based on the parent ID and name.

        Args:
            name (str):
                The name of the parent group to retrieve.
            parent_id (str | None):
                The ID of the parent process group.

        Returns:
            dict | None:
                Process group information, nor None if no process group
                with the given name is found under the specified parent.

        Example:
        {
            'revision': {
                'clientId': '3bce7da0-b8f7-41de-87af-7245ea7203e6',
                'version': 4
            },
            'id': '39fad8ec-0197-1000-0000-000042fa6c3d',
            'uri': 'https://nifi.master.terrarium.cloud:443/nifi-api/process-groups/39fad8ec-0197-1000-0000-000042fa6c3d',
            'position': {'x': 8.0, 'y': -48.0},
            'permissions': {
                'canRead': True,
                'canWrite': True
            },
            'bulletins': [],
            'component': {
                'id': '39fad8ec-0197-1000-0000-000042fa6c3d',
                'parentGroupId': '39e6026f-0197-1000-507c-19c44bb6d518',
                'position': {...},
                'name': 'KD_Integration',
                'comments': '',
                'parameterContext': {...},
                'flowfileConcurrency': 'UNBOUNDED',
                'flowfileOutboundPolicy': 'STREAM_WHEN_AVAILABLE',
                'defaultFlowFileExpiration': '0 sec',
                'defaultBackPressureObjectThreshold': 10000,
                'defaultBackPressureDataSizeThreshold': '1 GB',
                'logFileSuffix': '',
                'executionEngine': 'INHERITED',
                'maxConcurrentTasks': 1,
                'statelessFlowTimeout': '1 min',
                'runningCount': 57,
                'stoppedCount': 0,
                'invalidCount': 0,
                'disabledCount': 1,
                ...
            },
            'status': {
                'id': '39fad8ec-0197-1000-0000-000042fa6c3d',
                'name': 'KD_Integration',
                'statsLastRefreshed': '18:04:47 GMT',
                'aggregateSnapshot': {...}
            },
            'runningCount': 57,
            'stoppedCount': 0,
            'invalidCount': 0,
            'disabledCount': 1,
            'activeRemotePortCount': 0,
            'inactiveRemotePortCount': 0,
            'upToDateCount': 0,
            'locallyModifiedCount': 0,
            'staleCount': 0,
            'locallyModifiedAndStaleCount': 0,
            'syncFailureCount': 0,
            'localInputPortCount': 0,
            'localOutputPortCount': 0,
            'publicInputPortCount': 0,
            'publicOutputPortCount': 0,
            'parameterContext': {
                'id': 'd380a638-7b8d-39e4-bda8-c77fa2c7ddf0',
                'permissions': {...},
                'component': {...}
            },
            'inputPortCount': 0,
            'outputPortCount':
        }

        """

        # If no specific parent ID is provided we dtermine the root process ID:
        if parent_id is None:
            root_process_group = self.get_root_process_group()
            if not root_process_group:
                return None
            parent_id = root_process_group.get("id")
            if not parent_id:
                return None

        process_groups = self.get_process_groups(parent_process_group_id=parent_id)

        process_group = next(
            (group for group in process_groups if group["component"]["name"] == name),
            None,
        )

        return process_group

    # end method definition

    def get_process_group_by_name(self, name: str) -> dict | None:
        """Get a top-level process group based on the name.

        This is a pure convenience wrapper for get_process_group_by_parent_and_name()
        in cases you want to look process group under 'root'.

        Args:
            name (str):
                The name of the parent group to retrieve.

        Returns:
            dict | None:
                Process group information, nor None if no process group
                with the given name is found under the specified parent.

        """

        # We let the parent_id undefined (None) - this will deliver the
        # process group in root if it exists with the given name:
        return self.get_process_group_by_parent_and_name(name=name)

    # end method definition

    def upload_process_group(
        self, file_path: str, name: str, position_x: float = 0.0, position_y: float = 0.0
    ) -> dict | None:
        """Upload Nifi flow from JSON file.

        Args:
            file_path (str):
                Path to JSON file.
            name (str):
                Name of the group to be added.
            position_x (float, optional):
                The layout position of the flow on the X-axis. Optional. Default 0.0.
            position_y (float, optional):
                The layout position of the flow on the Y-axis. Optional. Default 0.0.

        Returns:
            dict | None:
                Request response. None in case an error has occured.

        """

        root_process_group = self.get_root_process_group()
        if not root_process_group:
            return None
        root_process_group_id = root_process_group.get("id")

        if not root_process_group_id:
            return None

        process_groups = self.get_process_groups(parent_process_group_id=root_process_group_id)

        group_exists = next(
            (True for group in process_groups if group["component"]["name"] == name),
            False,
        )

        if group_exists:
            self.logger.warning("Process group -> '%s' already exists!", name)
            return None

        request_url = self.config()["restUrl"] + "/process-groups/" + root_process_group_id + "/process-groups/upload"
        request_header = self.request_upload_header()

        # Upload the Template JSON file
        with open(file_path, "rb") as pg_file:
            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                data={
                    "positionX": str(position_x),
                    "positionY": str(position_y),
                    "groupName": name,
                    "clientId": "none",
                },
                files={"file": (file_path, pg_file, "multipart/form-data")},
            )

        if response:
            self.logger.debug(
                "The process group -> '%s' has been uploaded successfully!",
                name,
            )
            return response

        self.logger.error(
            "The process group -> '%s' could not be uploaded!",
            name,
        )

        return None

    # end method definition

    def get_flow_status(self) -> dict | None:
        """Get the flow status.

        Returns:
            dict | None:
                Status information of the flow.

        Example:
        {
            'controllerStatus': {
                'activeThreadCount': 1,
                'terminatedThreadCount': 0,
                'queued': '0 / 0 bytes',
                'flowFilesQueued': 0,
                'bytesQueued': 0,
                'runningCount': 57,
                'stoppedCount': 0,
                'invalidCount': 0,
                'disabledCount': 1,
                'activeRemotePortCount': 0,
                'inactiveRemotePortCount': 0,
                'upToDateCount': 0,
                'locallyModifiedCount': 0,
                'staleCount': 0,
                'locallyModifiedAndStaleCount': 0,
                'syncFailureCount': 0
            }
        }

        """

        request_url = self.config()["restUrl"] + "/flow/status"
        request_header = self.request_json_header()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Cannot get flow status!",
        )

    # end method definition

    def get_flow_config(self) -> dict | None:
        """Get the flow configuration.

        Returns:
            dict | None:
                Configuration information of the flow.

        Example:
        {
            'flowConfiguration': {
                'supportsManagedAuthorizer': False,
                'supportsConfigurableAuthorizer': False,
                'supportsConfigurableUsersAndGroups': False,
                'currentTime': '05:51:45 GMT',
                'timeOffset': 0,
                'defaultBackPressureObjectThreshold': 10000,
                'defaultBackPressureDataSizeThreshold': '1 GB'
            }
        }

        """

        request_url = self.config()["restUrl"] + "/flow/config"
        request_header = self.request_json_header()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Cannot get flow status!",
        )

    # end method definition

    def get_parameter_contexts(self) -> list | None:
        """Get the list of parameter contexts.

        Returns:
            list | None:
                The list of parameter contexts.

        """

        request_url = self.config()["restUrl"] + "/flow/parameter-contexts"
        request_header = self.request_json_header()

        parameter_contexts = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Cannot get parameter contexts!",
        )

        if not parameter_contexts:
            return None

        return parameter_contexts.get("parameterContexts")

    # end method definition

    def get_parameter_context_by_name(self, name: str) -> dict | None:
        """Get the parameter context with the given name.

        Returns:
            dict | None:
                The parameter contexts with the given name.

        """

        # Get a list of all parameter contexts:
        parameter_contexts = self.get_parameter_contexts()

        parameter_context = next(
            (context for context in parameter_contexts if context["component"]["name"] == name), None
        )

        if not parameter_context:
            self.logger.error("Cannot find parameter context with name -> '%s'!", name)
            return None

        return parameter_context

    # end method definition

    def update_parameter(
        self, component: str, parameter: str, value: str | float | bool, sensitive: bool = False, description: str = ""
    ) -> dict | None:
        """Update a parameter in a given parameter context.

        Args:
            component (str):
                Name of the component.
            parameter (str):
                Name of the parameter.
            value (str | float | bool):
                Value of the parameter.
            sensitive (bool, optional):
                Indication if parameter is sensitive. Defaults to False.
            description (str, optional):
                Description of the parameter.

        Returns:
            dict | None:
                The updated parameterContext as dict.

        Example:
        {
            'request': {
                'requestId': '8e111371-df57-4ef2-a36d-81fdc5158810',
                'uri': 'https://nifi.master.terrarium.cloud:443/nifi-api/parameter-contexts/efc9e58c-946a-3125-916a-278f528ac0ab/update-requests/8e111371-df57-4ef2-a36d-81fdc5158810',
                'lastUpdated': '05/29/2025 09:56:51.000 GMT',
                'complete': False,
                'percentCompleted': 0,
                'state': 'Stopping Affected Processors',
                'updateSteps': [
                    {
                        'description': 'Stopping Affected Processors',
                        'complete': False
                    },
                    {
                        'description': 'Disabling Affected Controller Services',
                        'complete': False
                    },
                    {
                        'description': 'Updating Parameter Context',
                        'complete': False
                    },
                    {
                        'description': 'Re-Enabling Affected Controller Services',
                        'complete': False
                    },
                    {
                        'description': 'Restarting Affected Processors',
                        'complete': False
                    }
                ],
                referencingComponents': [
                    {
                        'revision': {...},
                        'id': '516d8089-9886-307a-99ba-f08ce519f446',
                        'permissions': {...},
                        'bulletins': [...],
                        'component': {
                            'processGroupId': '1b5bd4d5-0197-1000-ffff-ffffd6a2b035',
                            'id': '516d8089-9886-307a-99ba-f08ce519f446',
                            'referenceType': 'PROCESSOR',
                            'name': 'Unreserve Document',
                            'state': 'RUNNING',
                            'activeThreadCount': 0,
                            'validationErrors': [
                                "'516d8089-9886-307a-99ba-f08ce519f446' validated against 'IDOL License Service' is invalid because IDOL License Service not enabled",
                                "'IDOL License Service' validated against '01832b88-cf15-3a46-9d80-6be6247aa276' is invalid because Controller Service with ID 01832b88-cf15-3a46-9d80-6be6247aa276 is disabled"
                            ]
                        },
                        'processGroup': {...},
                        'referenceType': 'PROCESSOR'
                    },
                    ...
                ]
            }
        }

        """

        # Find the parameter context by its name:
        parameter_context = self.get_parameter_context_by_name(name=component)
        if not parameter_context:
            self.logger.error(
                "Parameter -> '%s' could not be updated because the parameter context -> '%s' was not found!",
                parameter,
                component,
            )
            return None

        parameter_context_id = parameter_context["id"]

        json_body = {
            "revision": parameter_context["revision"],
            "disconnectedNodeAcknowledged": False,
            "id": parameter_context_id,
            "component": {
                "id": parameter_context_id,
                "name": component,
                "description": None,
                "parameters": [
                    {
                        "parameter": {
                            "name": parameter,
                            "sensitive": sensitive,
                            "description": description,
                            "value": value,
                        }
                    },
                ],
                "inheritedParameterContexts": [],
            },
        }

        request_url = self.config()["restUrl"] + "/parameter-contexts/" + parameter_context_id + "/update-requests"
        request_header = self.request_json_header()

        response = self.do_request(
            url=request_url, method="POST", headers=request_header, json_data=json_body, failure_message=""
        )

        if response:
            if sensitive:
                value = value[:2] + "*" * (len(value) - 2)
            self.logger.debug("Parameter -> '%s' has been updated to value -> '%s'.", parameter, value)
            return response

        self.logger.error(
            "Parameter -> '%s' could not be updated!",
            parameter,
        )

        return None

    # end method definition

    def start_all_processors(self, name: str) -> dict | None:
        """Start all processors in the process group given by its name.

        Args:
            name (str):
                The name of the group to start the processors for.

        Returns:
            dict | None:
                Response of the start command.

        """

        process_group = self.get_process_group_by_name(name=name)
        if not process_group:
            self.logger.error("Cannot find process group -> '%s' to start!", name)
            return None

        process_group_id = process_group["id"]

        request_url = self.config()["restUrl"] + "/flow/process-groups/" + process_group_id
        request_header = self.request_json_header()

        json_body = {"id": process_group_id, "state": "RUNNING"}

        response = self.do_request(url=request_url, method="PUT", headers=request_header, json_data=json_body)

        if response:
            self.logger.debug("All processors in process-group -> '%s' have been started...", name)
            return response

        self.logger.error(
            "Processors in process-group -> '%s' failed to start!",
            name,
        )

        return None

    # end method definition

    def get_controller_services(self, process_group_id: str) -> list | None:
        """Get the list of controller services for a process group.

        Args:
            process_group_id (str):
                The process group to retrieve controller services for.

        Returns:
            list | None:
                The list of process groups. None in case an error has occured.

        Example:
        [
            {
            "revision": {
                "version": 1
            },
            "id": "81076e51-13d4-3930-bb89-cd192ccb213a",
            "uri": "https://nifi.master.terrarium.cloud:443/nifi-api/controller-services/81076e51-13d4-3930-bb89-cd192ccb213a",
            "permissions": {
                "canRead": true,
                "canWrite": true
            },
            "bulletins": [],
            "parentGroupId": "337df1d6-0197-1000-ffff-ffffbc502fff",
            "component": {
                "id": "81076e51-13d4-3930-bb89-cd192ccb213a",
                "versionedComponentId": "e1e795b3-ce90-3eaa-a7fb-929c8bde75e1",
                "parentGroupId": "337df1d6-0197-1000-ffff-ffffbc502fff",
                "name": "StandardHttpContextMap",
                "type": "org.apache.nifi.http.StandardHttpContextMap",
                "bundle": {
                "group": "org.apache.nifi",
                "artifact": "nifi-http-context-map-nar",
                "version": "2.0.0"
                },
                "controllerServiceApis": [
                {
                    "type": "org.apache.nifi.http.HttpContextMap",
                    "bundle": {
                    "group": "org.apache.nifi",
                    "artifact": "nifi-standard-services-api-nar",
                    "version": "2.0.0"
                    }
                }
                ],
                "comments": "",
                "state": "ENABLED",
                "persistsState": false,
                "restricted": false,
                "deprecated": false,
                "multipleVersionsAvailable": false,
                "supportsSensitiveDynamicProperties": false,
                "properties": {
                "Maximum Outstanding Requests": "5000",
                "Request Expiration": "1 min"
                },
                "descriptors": {
                "Maximum Outstanding Requests": {
                    "name": "Maximum Outstanding Requests",
                    "displayName": "Maximum Outstanding Requests",
                    "description": "The maximum number of HTTP requests that can be outstanding at any one time. Any attempt to register an additional HTTP Request will cause an error",
                    "defaultValue": "5000",
                    "required": true,
                    "sensitive": false,
                    "dynamic": false,
                    "supportsEl": false,
                    "expressionLanguageScope": "Not Supported",
                    "dependencies": []
                },
                "Request Expiration": {
                    "name": "Request Expiration",
                    "displayName": "Request Expiration",
                    "description": "Specifies how long an HTTP Request should be left unanswered before being evicted from the cache and being responded to with a Service Unavailable status code",
                    "defaultValue": "1 min",
                    "required": true,
                    "sensitive": false,
                    "dynamic": false,
                    "supportsEl": false,
                    "expressionLanguageScope": "Not Supported",
                    "dependencies": []
                }
                },
                "inputPorts": [],
                "outputPorts": [],
                "schedulingPeriod": "1 sec",
            },
            ...
            "status" : {
                'runStatus': 'ENABLED',
                'validationStatus': 'VALID'
            }
        ]

        """

        request_url = self.config()["restUrl"] + "/flow/process-groups/" + process_group_id + "/controller-services"
        request_header = self.request_json_header()

        controller_services = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Failed to get controller services for process group -> '{}'".format(process_group_id),
        )

        if not controller_services:
            return None

        return controller_services.get("controllerServices", [])

    # end method definition

    def set_controller_services_state(self, name: str, state: str = "ENABLED", components: dict | None = None) -> bool:
        """Enable or disable Controller Services in the specified Process Group.

        Args:
            name (str):
                The name of the process group to enable the controller-services for.
            state (str, optional):
                Can either be "ENABLED" or "DISABLED". Default is "ENABLED".
            components (dict | None, optional):
                If provided the state is only set for the given components of the process group.
                If not provided ALL components will be enabled/disabled.
                The dictionary should have a structure like this:
                {
                    "key" : {
                        "clientId" : "clientId",
                        "lastModifier" : "lastModifier",
                        "version" : 2
                    }
                }

        Returns:
            dict | None:
                Response of the enable controller command.

        """

        state = state.upper()
        if state not in ["ENABLED", "DISABLED"]:
            self.logger.error(
                "Illegal state -> '%s' for process group controller service. Needs to be 'ENABLED' or 'DISABLED'!",
                state,
            )

        process_group = self.get_process_group_by_name(name=name)
        if not process_group:
            self.logger.error(
                "Cannot find process group -> '%s' to %s controller service for!",
                name,
                "enable" if state == "ENABLED" else "disable",
            )
            return None

        process_group_id = process_group["id"]

        request_url = self.config()["restUrl"] + "/flow/process-groups/" + process_group_id + "/controller-services"
        request_header = self.request_json_header()

        json_body = {"id": process_group_id, "state": state, "disconnectedNodeAcknowledged": False}
        if components:
            json_body["components"] = components

        response = self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            json_data=json_body,
            failure_message="Unable to set state -> '{}' for controller-services in process-group -> '{}'".format(
                state, name
            ),
            show_error=True,
        )

        return response

    # end method definition

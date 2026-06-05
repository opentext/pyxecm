"""OTCA stands for Content Aviator and is an OpenText offering for LLMM-based Agentic AI.

The REST API is documented here (OT internal):
https://confluence.opentext.com/display/CSAI/LLM+Project+REST+APIs

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2026, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import hashlib
import json
import logging
import platform
import sys
import time
from importlib.metadata import version

import requests

from pyxecm.otcs import OTCS

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otca"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

REQUEST_HEADERS = {"User-Agent": USER_AGENT, "accept": "application/json", "Content-Type": "application/json"}

REQUEST_TIMEOUT = 60.0
REQUEST_RETRY_DELAY = 20.0
REQUEST_MAX_RETRIES = 2


default_logger = logging.getLogger(MODULE_NAME)


class OTCA:
    """Interact with Content Aviator REST API."""

    AGENT = "ai"  # name of the agent role (used in messages)
    USER = "user"  # name of the user role (used in messages)

    logger: logging.Logger = default_logger

    def __init__(
        self,
        base_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        otcs_object: OTCS | None = None,
        inline_citation: bool = True,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the Content Aviator (OTCA) object.

        Args:
            base_url (str):
                The Content Aviator base URL.
            client_id (str):
                The OTDS OAuth client ID.
            client_secret (str):
                The OTDS OAuth client secret.
            content_system (dict | None, optional):
                Maps service type ("user", "service") to the auth variant
                ("xecm", "otcm", "xecm-direct", "otcm-direct", "none").
            otcs_object (OTCS | None, optional):
                The OTCS object.
            inline_citation (bool, optional):
                Enable/Disable citations in the answers. Default is True.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otca")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        self.otcs_object = otcs_object

        otca_config = {}

        # check if base_url ends with a slash and remove it to ensure consistency in endpoint URLs
        if base_url and base_url.endswith("/"):
            base_url = base_url[:-1]

        # Chat endpoints:
        otca_config["chatUrl"] = base_url + "/v1/chat"
        otca_config["healthUrl"] = base_url + "/health"
        otca_config["directChatUrl"] = base_url + "/v1/direct-chat"

        # Authentication endpoints:
        otca_config["authUrl"] = base_url + "/auth"
        otca_config["tokenUrl"] = base_url + "/token"

        # RAG endpoints:
        otca_config["contextUrl"] = base_url + "/v1/context"
        otca_config["embedUrl"] = base_url + "/v1/embeddings"
        otca_config["directEmbedUrl"] = base_url + "/v1/direct-embed"

        # Feedback and thread endpoints:
        otca_config["feedbackUrl"] = base_url + "/v1/feedback"
        otca_config["threadUrl"] = base_url + "/v1/thread"

        # Metadata endpoint:
        otca_config["metadataUrl"] = base_url + "/v1/metadata"

        # Stats endpoint:
        otca_config["usageStatsUrl"] = base_url + "/v1/usage-stats"

        # MCP Client endpoints:
        otca_config["mcpClientServersUrl"] = base_url + "/mcp-client/servers"
        otca_config["mcpClientToolsUrl"] = base_url + "/mcp-client/tools"
        otca_config["mcpClientToolsRefreshUrl"] = base_url + "/mcp-client/tools/refresh"
        otca_config["mcpClientHealthUrl"] = base_url + "/mcp-client/health"

        # MCP Server endpoints:
        otca_config["mcpServerAllToolsUrl"] = base_url + "/mcp-server/list/alltools"
        otca_config["mcpServerRegisterToolsUrl"] = base_url + "/mcp-server/register/tools"
        otca_config["mcpServerToolsUrl"] = base_url + "/mcp-server/list/tools"
        otca_config["mcpServerDeleteToolsUrl"] = base_url + "/mcp-server/tools"
        otca_config["mcpServerHealthUrl"] = base_url + "/mcp-server/health"

        otca_config["contentSystem"] = self.get_content_system()
        otca_config["clientId"] = client_id
        otca_config["clientSecret"] = client_secret
        otca_config["inlineCitation"] = inline_citation

        self._config = otca_config

        self._context = ""
        self._embed_token: str | None = None
        self._chat_token: str | None = None
        self._chat_token_hashed: str | None = None

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict: Configuration dictionary

        """

        return self._config

    # end method definition

    def get_context(self) -> str:
        """Return the current chat context (history).

        Returns:
            str:
                Chat history.

        """

        return self._context

    # end method definition

    def get_content_system(self) -> str | None:
        """Return the content system used for authentication.

        Returns:
            str | None:
                Content system name or None if not set.

        """

        # Get content_system from OTCS version (OTCS versions < 25.4 use "xecm", >= 25.4 use "otcm")
        if self.otcs_object and (cs_version := self.otcs_object.get_server_version()):
            if float(cs_version) < 25.4:
                return "xecm"
            else:
                return "otcm"
        else:
            return None

            # content_system or {"user": "xecm", "service": "xecm"}

    # end method definition

    def request_header(self, service_type: str = "user", content_type: str = "application/json") -> dict:
        """Return the request header used for requests.

        Consists of Bearer access token and Content Type

        Args:
            service_type (str, optional):
                Service type for which the header should be returned.
                Either "user" (otcsticket-based) or "service" (Bearer JWT).
                Defaults to "user".

            content_type (str, optional):
                Custom content type for the request.
                Typical values:
                * application/json - Used for sending JSON-encoded data
                * application/x-www-form-urlencoded - The default for HTML forms.
                  Data is sent as key-value pairs in the body of the request, similar to query parameters.
                * multipart/form-data - Used for file uploads or when a form includes non-ASCII characters

        Returns:
            dict: The request header values.

        """

        request_header = REQUEST_HEADERS

        if content_type:
            request_header["Content-Type"] = content_type

        # Configure default Content System
        content_system = self.get_content_system()

        if content_system is None:
            return request_header

        if service_type == "user":
            if self._chat_token is None:
                self.authenticate_user()

            if content_system == "xecm":
                request_header["Authorization"] = "Bearer {}".format(self._chat_token_hashed)
            if content_system == "otcm":
                request_header["Authorization"] = "Bearer {}".format(self._chat_token)
            elif content_system in {"xecm-direct", "otcm-direct"}:
                request_header["otcsticket"] = self._chat_token

        elif service_type == "service":
            if self._embed_token is None:
                self.authenticate_service()
            request_header["Authorization"] = "Bearer {}".format(self._embed_token)

        return request_header

    # end method definition

    def do_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        params: dict | None = None,
        data: dict | list | None = None,
        json_data: dict | None = None,
        files: dict | None = None,
        timeout: float | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        retry_forever: bool = False,
        parse_request_response: bool = True,
    ) -> dict | None:
        """Call an Content Aviator REST API in a safe way.

        Args:
            url (str):
                URL to send the request to.
            method (str, optional):
                HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional):
                Request headers. Defaults to None.
            params (dict | None, optional):
                URL query string parameters. Defaults to None.
            data (dict | None, optional):
                Request payload. Defaults to None.
            json_data (dict | None, optional):
                Request payload for the JSON parameter. Defaults to None.
            files (dict | None, optional):
                Dictionary of {"name": file-tuple} for multipart encoding upload.
                The file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple
                ("filename", fileobj, "content_type").
            timeout (float | None, optional):
                Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed REST call.
                If False, then only a warning is logged. Defaults to True.
            failure_message (str, optional):
                Specific error message. Defaults to "".
            success_message (str, optional):
                Specific success message. Defaults to "".
            max_retries (int, optional):
                Number of retries on connection errors. Defaults to REQUEST_MAX_RETRIES.
            retry_forever (bool, optional):
                Whether to wait forever without timeout. Defaults to False.
            parse_request_response (bool, optional):
                Whether the response text should be interpreted as JSON and loaded
                into a dictionary. Defaults to True.

        Returns:
            dict | None:
                Response of Content Aviator REST API or None in case of an error.

        """

        retries = 0
        while True:
            try:
                self.logger.debug(
                    "Sending %s request ->\nurl: %s\nheaders: %s\nparams: %s\ndata: %s\njson: %s\nfiles: %s\ntimeout: %s",
                    method,
                    url,
                    json.dumps(headers, indent=2),
                    params,
                    json.dumps(data, indent=2),
                    json.dumps(json_data, indent=2),
                    files,
                    timeout,
                )

                response = requests.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json_data,
                    files=files,
                    headers=headers,
                    timeout=timeout,
                )

                if response.ok:
                    if success_message:
                        self.logger.debug(success_message)
                    if parse_request_response:
                        return self.parse_request_response(response, show_error=show_error)
                    else:
                        return response
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    self.logger.debug("Session has expired - try to re-authenticate...")
                    self.authenticate_user()
                    retries += 1
                else:
                    # Handle plain HTML responses to not pollute the logs
                    content_type = response.headers.get("content-type", None)
                    response_text = "HTML content (see debug log)" if content_type == "text/html" else response.text

                    if show_error:
                        self.logger.error(
                            "%s; status -> %s; error -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )
                    else:
                        self.logger.warning(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )

                    if content_type == "text/html":
                        self.logger.debug(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
                            response.text,
                        )

                    return None
            except requests.exceptions.Timeout:
                if retries <= max_retries or max_retries < 0:
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
                if retries <= max_retries or max_retries < 0:
                    self.logger.warning(
                        "Connection error (%s)! Retrying in %d seconds... %d/%d",
                        url,
                        REQUEST_RETRY_DELAY,
                        retries,
                        max_retries,
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    self.logger.error(
                        "%s; connection error!",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                        self.logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                        time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                    else:
                        return None

    # end method definition

    def parse_request_response(
        self,
        response_object: requests.Response,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> list | None:
        """Convert the request response (JSon) to a Python list in a safe way that also handles exceptions.

        It first tries to load the response.text
        via json.loads() that produces a dict output. Only if response.text is
        not set or is empty it just converts the response_object to a dict using
        the vars() built-in method.

        Args:
            response_object (requests.Response):
                This is reponse object delivered by the request call.
            additional_error_message (str, optional):
                Use a more specific error message in case of an error.
            show_error (bool, optional):
                If True, write an error to the log file.
                If False, write a warning to the log file.

        Returns:
            list | None:
                The response information or None in case of an error.

        """

        if not response_object:
            return None

        try:
            list_object = json.loads(response_object.text) if response_object.text else vars(response_object)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSON. {}; error -> {}".format(
                    additional_error_message,
                    exception,
                )
            else:
                message = "Cannot decode response as JSON; error -> {}".format(
                    exception,
                )
            if show_error:
                self.logger.error(message)
            else:
                self.logger.warning(message)
            return None
        else:
            return list_object

    # end method definition

    def authenticate_user(self) -> str | None:
        """Authenticate an end-user via the Content Aviator POST /auth endpoint.

        Obtains an OTCS ticket using the OTCS object's credentials.
        If the OTCS object already has a ticket, it is reused directly.

        Returns:
            str | None:
                Authentication token or None if the authentication fails.

        """

        if self.otcs_object is None:
            msg = "OTCS Object is not defined, authentication failed."
            raise AttributeError(msg)

        # Try to reuse an existing ticket first:
        token = self.otcs_object.otcs_ticket()

        # If no ticket exists, authenticate via the /auth endpoint:
        if not token:
            username = self.otcs_object.get_username() if hasattr(self.otcs_object, "get_username") else None
            password = self.otcs_object.get_password() if hasattr(self.otcs_object, "get_password") else None

            if not username or not password:
                # Fall back to direct OTCS authentication:
                token = self.otcs_object.authenticate()
                if isinstance(token, dict) and "otcsticket" in token:
                    token = token["otcsticket"]
            else:
                url = self.config()["authUrl"]
                data = {
                    "username": username,
                    "password": password,
                }
                result = self.do_request(
                    url=url,
                    method="POST",
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded", "accept": "application/json"},
                )
                if result:
                    token = result.get("otcsticket")
                else:
                    self.logger.error("Authentication failed via /auth endpoint -> %s", url)
                    return None

        if isinstance(token, dict) and "otcsticket" in token:
            token = token["otcsticket"]

        if token:
            self._chat_token = token

            # Encode the input string before hashing
            encoded_string = token.encode("utf-8")

            # Create a new SHA-512 hash object
            sha512 = hashlib.sha512()

            # Update the hash object with the input string
            sha512.update(encoded_string)

            # Get the hexadecimal representation of the hash
            hashed_output = sha512.hexdigest()

            self._chat_token_hashed = hashed_output

            return self._chat_token

        else:
            self.logger.error("Authentication failed. Token not found.")

            return None

    # end method definition

    def authenticate_service(self) -> str | None:
        """Authenticate a service client via the Content Aviator POST /token endpoint.

        Uses client credentials (client_id / client_secret) to obtain a bearer
        token used for service-to-service calls (e.g. embeddings ingestion).

        Returns:
            str | None:
                Authentication token or None if the authentication fails.

        """

        url = self.config()["tokenUrl"]

        data = {
            "client_id": self.config()["clientId"],
            "client_secret": self.config()["clientSecret"],
        }

        result = self.do_request(
            url=url,
            method="POST",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded", "accept": "application/json"},
        )

        if result:
            self._embed_token = result["token"]
            return self._embed_token
        else:
            self.logger.error(
                "Authentication failed with client ID -> '%s' against -> %s", self.config()["clientId"], url
            )
            return None

    # end method definition

    def chat(
        self,
        context: str | None,
        messages: list,
        where: list | None = None,
        service_type: str = "user",
        caller: str | None = None,
        inline_citation: bool = True,
    ) -> dict:
        """Process a chat interaction with Content Aviator.

        Chat requests are meant to be called as end-users.  This should involve
        passing the end-user's access token via the Authorization HTTP header.
        The chat service use OTDS's token endpoint to ensure that the token is valid.

        Args:
            context (str | None):
                Context for the current conversation
                (empty initially, returned by previous responses from POST /v1/chat).
            messages (list):
                List of messages from conversation history.
                TODO: document the message format. Especially which values the auther key can have.
            where (list):
                Metadata name/value pairs for the query.
                Could be used to specify workspaces, documents, or other criteria in the future.
                Values need to match those passed as metadata to the embeddings API.
            service_type (str, optional):
                Auth type: "user" (otcsticket) or "service" (Bearer JWT). Default is "user".
            caller (str | None, optional):
                Caller identifier for the request. Default is None.
            inline_citation (bool, optional):
                Whether to extract and display inline citations from responses.
                Default is True.

        Returns:
            dict:
                Conversation status

        Example:
        {
            'result': 'I do not know.',
            'called': [
                {
                    'name': 'breakdown_query',
                    'arguments': {},
                    'result': '```json{"input": ["Tell me about the calibration equipment"]}```',
                    'showInContext': False
                },
                {
                    'name': 'store_subqueries',
                    'arguments': {
                        '0': 'Tell me about the calibration equipment'
                    },
                    'showInContext': False
                },
                {
                    'name': 'get_next_subquery_and_reset_segment',
                    'arguments': {},
                    'result': 'Tell me about the calibration equipment',
                    'showInContext': False
                },
                {
                    'name': 'segmented_query',
                    'arguments': {},
                    'result': 'runQuery',
                    'showInContext': False
                },
                {
                    'name': 'get_context',
                    'arguments': {
                        'query': 'Tell me about the calibration equipment'
                    },
                    'result': '',
                    'showInContext': True
                },
                {
                    'name': 'check_answer',
                    'arguments': {},
                    'result': 'noAnswer',
                    'showInContext': False
                },
                {
                    'name': 'segmented_query',
                    'arguments': {},
                    'result': 'answer',
                    'showInContext': False
                },
                {
                    'name': 'get_next_subquery_and_reset_segment',
                    'arguments': {},
                    'showInContext': False
                },
                {
                    'name': 'general_prompt',
                    'arguments': {...},
                    'result': 'I do not know.',
                    'showInContext': False
                },
                {
                    'name': 'filter_references',
                    'arguments': {},
                    'result': '[]',
                    'showInContext': False
                }
            ],
            'references': [],
            'context': 'Tool "get_context" called with arguments {"query":"Tell me about the calibration equipment"} and returned:',
            'queryMetadata': {
                'originalQuery': 'Tell me about the calibration equipment',
                'usedQuery': 'Tell me about the calibration equipment'
            }
        }

        """

        request_url = self.config()["chatUrl"]
        request_header = self.request_header(service_type=service_type)

        chat_data = {
            "context": context,
            "messages": messages,
            "inlineCitation": inline_citation,
        }

        if where:
            chat_data["where"] = where
        if caller:
            chat_data["caller"] = caller

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=chat_data,
            timeout=None,
            failure_message="Failed to chat with Content Aviator",
        )

    # end method definition

    def feedback(
        self,
        question: str,
        answer: str,
        rating: str,
        context: str | None = None,
        trace_id: str | None = None,
        comment: str | None = None,
    ) -> dict | None:
        """Submit feedback for a chat interaction.

        Args:
            question (str):
                The question that was asked.
            answer (str):
                The answer that was received.
            rating (str):
                Rating for the answer. Must be "UP" or "DOWN".
            context (str | None, optional):
                Optional context for the feedback.
            trace_id (str | None, optional):
                Trace ID for the interaction being rated.
            comment (str | None, optional):
                Optional comment providing more details about the feedback.

        Returns:
            dict | None:
                REST API response or None in case of an error.

        """

        if rating not in ("UP", "DOWN"):
            self.logger.error("Invalid feedback rating -> '%s'. Must be 'UP' or 'DOWN'.", rating)
            return None

        request_url = self.config()["feedbackUrl"]
        request_header = self.request_header(service_type="user")

        feedback_data = {
            "question": question,
            "answer": answer,
            "rating": rating,
        }
        if context is not None:
            feedback_data["context"] = context
        if trace_id is not None:
            feedback_data["trace_id"] = trace_id
        if comment is not None:
            feedback_data["comment"] = comment

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=feedback_data,
            failure_message="Failed to submit feedback",
        )

    # end method definition

    def thread(self, thread_id: str) -> dict | None:
        """Retrieve the chat conversation history by its thread ID.

        Args:
            thread_id (str):
                The conversation thread ID.

        Returns:
            dict | None:
                Conversation history or None in case of an error.

        """

        request_url = self.config()["threadUrl"]
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            params={"thread_id": thread_id},
            failure_message="Failed to retrieve thread -> '{}'".format(thread_id),
        )

    # end method definition

    def context(
        self,
        query: str,
        document_ids: list | None = None,
        workspace_ids: list | None = None,
        threshold: float = 0.3,
        num_results: int = 20,
    ) -> dict:
        """Get semantic context for a given query string.

        Search requests are meant to be called as end-users. This should involve
        passing the end-user's access token via the Authorization HTTP header.
        The chat service use OTDS's token endpoint to ensure that the token is valid.

        Args:
            query (str):
                The query.
            document_ids (list, optional):
                List of documents (IDs) to use as scope for the query.
            workspace_ids (list, optional):
                List of workspaces (IDs) to use as scope for the query.
            threshold (float, optional):
                Minimum similarity score to accept a document. A value like 0.7 means
                only bring back documents that are at least 70% similar.
            num_results (int, optional):
                Also called "top-k". Defined how many "most similar" documents to retrieve.
                Typical value: 3-20. Higher values gets broader context but risks pulling
                in less relevant documents.

        Returns:
            dict:
                Results of the search.

        Example:
        [
            {
                "pageContent": "matched chunk"
                "metadata": {
                    "documentID": 1234,
                    "workspaceID": 4711,
                    "some-id": 123
                },
                "distance": 0.13
            },
            {
                "pageContent": "matched chunk1"
                "metadata": {
                    "documentID": 5678,
                    "workspaceID": 47272
                },
                "distance": 0.22
            }
        ]

        """

        if workspace_ids is None:
            workspace_ids = []

        if document_ids is None:
            document_ids = []

        request_url = self.config()["contextUrl"]
        request_header = self.request_header(service_type="user")

        search_data = {
            "query": query,
            "threshold": threshold,
            "numResults": num_results,
            "metadata": [],
        }

        for document_id in document_ids or []:
            search_data["metadata"].append({"documentID": str(document_id)})
        for workspace_id in workspace_ids or []:
            search_data["metadata"].append({"workspaceID": str(workspace_id)})

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=search_data,
            timeout=None,
            failure_message="Failed to to do a semantic search with query -> '{}'".format(query),
        )

    # end method definition

    def embed(
        self,
        content: str | None = None,
        operation: str = "add",
        document_id: int | None = None,
        workspace_id: int | None = None,
        additional_metadata: dict | None = None,
    ) -> dict | None:
        """Embed a given content.

        Requests are meant to be called as a service user. This would involve passing a service user's access token
        (token from a particular OAuth confidential client, using client credentials grant).

        Args:
            content (str | None):
                Content to be embedded. This is a document chunk. Can be empty for "delete" operations.
            operation (str, optional):
                This can be either "add", "update" or "delete".
            document_id (int | None, optional):
                The ID of the document the content originates from. This becmes metadata in the vector store.
            workspace_id (int | None, optional):
                The ID of the workspace the content originates from. This becomes metadata in the vector store.
            additional_metadata (dict | None, optional):
                Dictionary with additional metadata.

        Returns:
            dict | None:
                REST API response or None in case of an error.

        Example:
        {
            'status': 'accepted'
        }

        """

        # Validations:
        if operation not in ["add", "update", "delete"]:
            self.logger.error("Illegal embed operation -> '%s'!", operation)
            return None
        if operation != "delete" and not content:
            self.logger.error("Add or update operation require content to embed!")
            return None

        request_url = self.config()["embedUrl"]
        request_header = self.request_header(service_type="service")

        metadata = {}
        if workspace_id:
            metadata["workspaceID"] = workspace_id
        if document_id:
            metadata["documentID"] = document_id
        if additional_metadata:
            metadata.update(additional_metadata)

        embed_data = {
            "content": content,
            "operation": operation,
            "metadata": metadata,
        }

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=embed_data,
            timeout=None,
            failure_message="Failed to embed content",
        )

    # end method definition

    def metadata(
        self,
        content: str | dict | None = None,
        operation: str = "add",
        document_id: int | None = None,
        workspace_id: int | None = None,
        additional_metadata: dict | None = None,
    ) -> dict | None:
        """Submit document metadata for embedding.

        This endpoint processes metadata for documents without embedding the content itself.
        Uses the same request model as embed() but targets the /v1/metadata endpoint.

        Args:
            content (str | dict | None):
                Content or metadata to process. Can be empty for "delete" operations.
            operation (str, optional):
                This can be either "add", "update" or "delete".
            document_id (int | None, optional):
                The ID of the document.
            workspace_id (int | None, optional):
                The ID of the workspace.
            additional_metadata (dict | None, optional):
                Dictionary with additional metadata.

        Returns:
            dict | None:
                REST API response or None in case of an error.

        """

        if operation not in ("add", "update", "delete"):
            self.logger.error("Illegal metadata operation -> '%s'!", operation)
            return None

        request_url = self.config()["metadataUrl"]
        request_header = self.request_header(service_type="service")

        metadata = {}
        if workspace_id:
            metadata["workspaceID"] = workspace_id
        if document_id:
            metadata["documentID"] = document_id
        if additional_metadata:
            metadata.update(additional_metadata)

        metadata_data = {
            "content": content,
            "operation": operation,
            "metadata": metadata,
        }

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=metadata_data,
            timeout=None,
            failure_message="Failed to submit metadata",
        )

    # end method definition

    def direct_embed(
        self,
        content: list[str] | None = None,
    ) -> dict | None:
        """Direct embed a given a list of strings. Generates embeddings without storing them.

        Args:
            content (list[str] | None):
                Content to be embedded. This is a list of strings.

        Returns:
            dict | None:
                REST API response or None in case of an error.

        Example:
        {
            'vectors': [
                [-0.04728065803647041, -0.006598987616598606, ...],
                [...]
            ],
            'model': 'text-multilingual-embedding-002'
        }

        """

        request_url = self.config()["directEmbedUrl"]
        request_header = self.request_header(service_type="user")

        embed_data = {
            "content": content,
        }

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=embed_data,
            timeout=None,
            failure_message="Failed to embed content",
        )

    # end method definition

    def direct_chat(
        self,
        messages: list | None = None,
        options: dict | None = None,
        chat_id: str | None = None,
    ) -> dict | None:
        """Chat with a LLM directly. This is bypassing the configured LangGraph completely.

        Args:
            messages (list | None, optional):
                List of messages including conversation history. Each list element is
                a dictionary with two keys: "author" and "content".
                Example: [{"author": "user", "content": "What is the recommended fridge temperature?"}]
            options (dict | None, optional):
                Options for the LLM model. Supported keys:
                * model (str) - e.g. "gemini-2.5-flash-lite"
                * temperature (float) - e.g. 0.7
            chat_id (str | None, optional):
                Unique identifier for the chat session.

        Returns:
            dict | None:
                The response from the LLM.

        Example:
        {
            'result': 'The recommended fridge temperature for optimal food safety and freshness is between **35°F and 38°F (1.7°C and 3.3°C)...',
            'chatID': None
        }

        """

        request_url = self.config()["directChatUrl"]
        request_header = self.request_header(service_type="user")
        request_data = {
            "messages": messages,
        }
        if options is not None:
            request_data["options"] = options
        if chat_id is not None:
            request_data["chatID"] = chat_id

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=request_data,
            timeout=None,
            show_error=True,
            failure_message="Failed to chat with LLM -> '{}'".format(
                options.get("model", "<default model>") if options else "<default model>"
            ),
        )

        return response

    # end method definition

    def usage_stats(
        self,
        tenant_id: str | None = None,
        units: str = "days",
        from_offset: int | None = None,
        to_offset: int | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
    ) -> dict | None:
        """Retrieve usage statistics for the Content Aviator service.

        Supports either relative offsets (from_offset/to_offset) or
        absolute dates (from_date/to_date) for specifying the time range.

        Args:
            tenant_id (str | None, optional):
                Tenant ID to query. Falls back to auth context if not provided.
            units (str, optional):
                Reporting time unit. Must be "days", "months", or "years".
                Default is "days".
            from_offset (int | None, optional):
                Relative start offset in units from today (e.g. -30 for 30 days ago).
                Must be <= 0.
            to_offset (int | None, optional):
                Relative end offset in units from today. Must be <= 0.
                Defaults to 0 (today) on the server side.
            from_date (str | None, optional):
                Absolute start date in YYYY-MM-DD format (inclusive, UTC).
            to_date (str | None, optional):
                Absolute end date in YYYY-MM-DD format (inclusive, UTC).

        Returns:
            dict | None:
                Usage statistics or None in case of an error.

        Example:
        {
            'tenantId': 'aviator',
            'timezone': 'UTC',
            'units': 'days',
            'from': '2026-05-18',
            'to': '2026-05-18',
            'data': [
                {
                    'date': '2026-05-18',
                    'chatCount': 34,
                    'directChatCount': 12,
                    'embeddingsRequestCount': 7929,
                    'chunksCount': 37688,
                    'documentsEmbeddedCount': 7929,
                    'chunksDeletedCount': 0,
                    'documentsDeletedCount': 0,
                    'semanticQueryCount': 4,
                    'input_tokens': 1285821,
                    'output_tokens': 99023,
                    'llm_total_requests': 255
                }
            ],
            'semanticSize': {
                'documentsEmbeddedTotal': 7929,
                'chunksTotal': 37688
            }
        }

        """

        request_url = self.config()["usageStatsUrl"]
        request_header = self.request_header(service_type="user")

        params = {"units": units}
        if tenant_id is not None:
            params["tenant_id"] = tenant_id
        if from_offset is not None:
            params["from_offset"] = from_offset
        if to_offset is not None:
            params["to_offset"] = to_offset
        if from_date is not None:
            params["from_date"] = from_date
        if to_date is not None:
            params["to_date"] = to_date

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            params=params,
            failure_message="Failed to retrieve usage statistics",
        )

    # end method definition

    def is_ready(self, wait: bool = False) -> bool | None:
        """Check if service is ready to be used.

        Args:
            wait (bool, optional):
                If True, will wait until the service is ready.
                Default is False.

        Returns:
            bool | None:
                True if ready, False if not, None if unknown service.

        """

        request_url = self.config()["healthUrl"]

        if wait:
            self.logger.info("Waiting for Aviator service to be available at %s ...", request_url)

        response = None
        while not response:
            response = self.do_request(
                url=request_url,
                method="GET",
                max_retries=-1,
                timeout=None,
                show_error=False,
                failure_message="Content Aviator is not available!",
                parse_request_response=False,
            )

            if not wait:
                break

        # Return True if we got a response, False if not:
        return response is not None

    # end method definition

    # --- MCP Client Methods ---

    def create_mcp_server(self, server_config: dict) -> dict | None:
        """Create a new MCP server configuration.

        Args:
            server_config (dict):
                Server configuration including:
                * name (str) - Unique identifier for the server.
                * active (bool) - Whether the server is enabled. Default is True.
                * url (str | None) - URL for HTTP-based servers.
                * transport (str) - Transport type: "streamable_http", "sse", or "stdio".
                * command (str | None) - Command for STDIO servers.
                * args (list[str]) - Arguments for STDIO command.
                * tool_scope (str) - Where tools should be available: "default" or "custom".
                * auth_schema (dict | None) - Authentication configuration.

        Returns:
            dict | None:
                Created server configuration or None in case of an error.

        """

        request_url = self.config()["mcpClientServersUrl"]
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=server_config,
            failure_message="Failed to create MCP server configuration",
        )

    # end method definition

    def list_mcp_servers(self) -> list | None:
        """List all MCP server configurations.

        Returns:
            list | None:
                List of MCP server configurations or None in case of an error.

        """

        request_url = self.config()["mcpClientServersUrl"]
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Failed to list MCP server configurations",
        )

    # end method definition

    def get_mcp_server(self, server_id: str) -> dict | None:
        """Get a single MCP server configuration.

        Args:
            server_id (str):
                Unique identifier of the MCP server.

        Returns:
            dict | None:
                MCP server configuration or None in case of an error.

        """

        request_url = self.config()["mcpClientServersUrl"] + "/" + server_id
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Failed to get MCP server -> '{}'".format(server_id),
        )

    # end method definition

    def update_mcp_server(self, server_id: str, server_config: dict) -> dict | None:
        """Update an existing MCP server configuration.

        Args:
            server_id (str):
                Unique identifier of the MCP server to update.
            server_config (dict):
                Updated server configuration. See create_mcp_server() for supported keys.

        Returns:
            dict | None:
                Updated server configuration or None in case of an error.

        """

        request_url = self.config()["mcpClientServersUrl"] + "/" + server_id
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            json_data=server_config,
            failure_message="Failed to update MCP server -> '{}'".format(server_id),
        )

    # end method definition

    def delete_mcp_server(self, server_id: str) -> dict | None:
        """Delete an MCP server configuration.

        Args:
            server_id (str):
                Unique identifier of the MCP server to delete.

        Returns:
            dict | None:
                REST API response or None in case of an error.

        """

        request_url = self.config()["mcpClientServersUrl"] + "/" + server_id
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            failure_message="Failed to delete MCP server -> '{}'".format(server_id),
        )

    # end method definition

    def list_mcp_tools(self) -> list | None:
        """List all tools available from remote MCP servers.

        Returns:
            list | None:
                List of available MCP tools or None in case of an error.

        """

        request_url = self.config()["mcpClientToolsUrl"]
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Failed to list MCP tools",
        )

    # end method definition

    def refresh_mcp_tools(self) -> dict | None:
        """Force re-discovery of tools from all configured MCP servers.

        Returns:
            dict | None:
                REST API response or None in case of an error.

        """

        request_url = self.config()["mcpClientToolsRefreshUrl"]
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            failure_message="Failed to refresh MCP tools",
        )

    # end method definition

    def mcp_client_health(self) -> dict | None:
        """Check health of the MCP client and its configured servers.

        Returns:
            dict | None:
                Health status including mcp_enabled, total_servers,
                connected_servers, total_tools, and health_status.

        """

        request_url = self.config()["mcpClientHealthUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            failure_message="Failed to check MCP client health",
        )

    # end method definition

    # --- MCP Server Methods ---

    def list_all_mcp_tools(self) -> list | None:
        """List all discovered tools on the Aviator MCP server.

        Returns:
            list | None:
                List of all discovered tools or None in case of an error.

        """

        request_url = self.config()["mcpServerAllToolsUrl"]
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Failed to list all MCP server tools",
        )

    # end method definition

    def register_mcp_tools(self, tools: list[str]) -> dict | None:
        """Register tools for the calling tenant.

        Args:
            tools (list[str]):
                List of tool names to register.

        Returns:
            dict | None:
                Registration response or None in case of an error.

        """

        request_url = self.config()["mcpServerRegisterToolsUrl"]
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data={"tools": tools},
            failure_message="Failed to register MCP tools",
        )

    # end method definition

    def list_registered_mcp_tools(self) -> list | None:
        """List tools registered for the calling tenant.

        Returns:
            list | None:
                List of registered tools or None in case of an error.

        """

        request_url = self.config()["mcpServerToolsUrl"]
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            failure_message="Failed to list registered MCP tools",
        )

    # end method definition

    def delete_registered_mcp_tools(self, tools: list[str]) -> dict | None:
        """Delete registered tools for the calling tenant.

        Args:
            tools (list[str]):
                List of tool names to unregister.

        Returns:
            dict | None:
                REST API response or None in case of an error.

        """

        request_url = self.config()["mcpServerDeleteToolsUrl"]
        request_header = self.request_header(service_type="user")

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            json_data={"tools": tools},
            failure_message="Failed to delete registered MCP tools",
        )

    # end method definition

    def mcp_server_health(self) -> dict | None:
        """Check health of the Aviator MCP server.

        Returns:
            dict | None:
                Health status including mcp_enabled, total_tools,
                and health_status.

        """

        request_url = self.config()["mcpServerHealthUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            failure_message="Failed to check MCP server health",
        )

    # end method definition

"""OTCA stands for Content Aviator and is an OpenText offering for LLMM-based Agentic AI.

The REST API is documented here (OT internal):
https://confluence.opentext.com/display/CSAI/LLM+Project+REST+APIs

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import hashlib
import json
import logging
import platform
import sys
import time
import urllib.parse
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

DEFAULT_LLM_ATTRIBUTES = {
    "temperature": 0.2,
    "maxTokens": 8000,
    "maxRetries": 2,
    "topK": 40,
    "topP": 0.8,
    "cache": False,
}

default_logger = logging.getLogger(MODULE_NAME)


class OTCA:
    """Interact with Content Aviator / Aviator Studio REST API."""

    AGENT = "ai"  # name of the agent role (used in messages)
    USER = "user"  # name of the user role (used in messages)

    logger: logging.Logger = default_logger

    def __init__(
        self,
        chat_url: str | None = None,
        embed_url: str | None = None,
        studio_url: str | None = None,
        otds_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        content_system: dict | None = None,
        otcs_object: OTCS | None = None,
        synonyms: list | None = None,
        inline_citation: bool = True,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the Content Aviator (OTCA) object.

        Args:
            chat_url (str):
                The Content Aviator base URL for chat.
            embed_url (str):
                The Content Aviator base URL for embedding.
            studio_url (str):
                The base URL of Content Aviator Studio.
            otds_url (str):
                The OTDS URL.
            client_id (str):
                The Core Share Client ID.
            client_secret (str):
                The Core Share client secret.
            content_system (dict | None, optional):
                The Content System configuration for the services which control the authentication.
            otcs_object (OTCS | None, optional):
                The OTCS object..
            synonyms (list | None, optional):
                List of synonyms that are used to generate a better response to the user.
            inline_citation (bool, optional):
                Enable/Disable citations in the answers. Default is True.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otca")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        otca_config = {}

        otca_config["studioUrl"] = studio_url.rstrip("/")

        # Health and Readiness endpoints:
        otca_config["livenessUrl"] = otca_config["studioUrl"] + "/liveness"
        otca_config["readinessUrl"] = otca_config["studioUrl"] + "/readiness"

        # Chat endpoints:
        otca_config["chatUrl"] = chat_url + "/v1/chat"
        otca_config["directChatUrl"] = chat_url + "/v1/direct-chat"

        # RAG endpoints:
        otca_config["semanticSearchUrl"] = studio_url.rstrip("/") + "/api/v1/semantic_search"
        otca_config["contextUrl"] = studio_url.rstrip("/") + "/v1/context"
        otca_config["embedUrl"] = embed_url + "/v1/embeddings"
        otca_config["directEmbedUrl"] = embed_url + "/v1/direct-embed"

        # Aviator Studio endpoints:
        otca_config["studioAgentsUrl"] = otca_config["studioUrl"] + "/studio/v1/agents"
        otca_config["studioToolsUrl"] = otca_config["studioUrl"] + "/studio/v1/tools"
        otca_config["studioGraphsUrl"] = otca_config["studioUrl"] + "/studio/v1/graphs"
        otca_config["studioRulesUrl"] = otca_config["studioUrl"] + "/studio/v1/rules"
        otca_config["studioPromptsUrl"] = otca_config["studioUrl"] + "/studio/v1/prompts"
        otca_config["studioLLModelsUrl"] = otca_config["studioUrl"] + "/studio/v1/llmmodels"
        otca_config["studioImportUrl"] = otca_config["studioUrl"] + "/studio/v1/import"
        otca_config["studioExportUrl"] = otca_config["studioUrl"] + "/studio/v1/export"

        # Studio 'low-level' APIs:
        otca_config["studioModelsUrl"] = otca_config["studioUrl"] + "/studio/v1/api/models"
        otca_config["studioTenantsUrl"] = otca_config["studioModelsUrl"] + "/tenants"
        otca_config["scratchPadUrl"] = otca_config["studioUrl"] + "/v1/scratchpad"

        otca_config["contentSystem"] = content_system if content_system else {"chat": "xecm", "embed": "xecm"}
        otca_config["clientId"] = client_id
        otca_config["clientSecret"] = client_secret
        otca_config["otdsUrl"] = otds_url.rstrip("/")

        otca_config["synonyms"] = synonyms if synonyms else []
        otca_config["inlineCitation"] = inline_citation

        self._config = otca_config
        self.otcs_object = otcs_object

        self._context = ""
        self._embed_token: str | None = None
        self._chat_token: str | None = None
        self._chat_token_hashed: str | None = None
        self._studio_token: str | None = None
        self._node_dictionary: dict = {}

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

    def get_synonyms(self) -> list:
        """Get configured synonyms.

        Returns a list of lists. The inner lists are the set
        of terms that are synonyms of each other.

        Args:
            synonyms (list):
                List of synonyms that are used to generate a better response to the user.

        """

        return self.config()["synonyms"]

    # end method definition

    def add_synonyms(self, synonyms: list) -> None:
        """Add synonyms to the existing synonyms.

        Args:
            synonyms (list):
                List of synonyms that are used to generate a better response to the user.

        """

        self.config()["synonyms"].extend(synonyms)

    # end method definition

    def request_header(self, service_type: str = "chat", content_type: str = "application/json") -> dict:
        """Return the request header used for requests.

        Consists of Bearer access token and Content Type

        Args:
            service_type (str, optional):
                Service type for which the header should be returned.
                Either "chat" or "embed". "chat" is the default.

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
        content_system = self.config()["contentSystem"].get(service_type, "none")

        if content_system == "none":
            return request_header

        if service_type == "chat":
            if self._chat_token is None:
                self.authenticate_chat()

            if content_system == "xecm":
                request_header["Authorization"] = "Bearer {}".format(self._chat_token_hashed)
            if content_system == "otcm":
                request_header["Authorization"] = "Bearer {}".format(self._chat_token)
            elif content_system in {"xecm-direct", "otcm-direct"}:
                request_header["otcsticket"] = self._chat_token

        elif service_type == "embed":
            if self._embed_token is None:
                self.authenticate_embed()
            request_header["Authorization"] = "Bearer {}".format(self._embed_token)
        elif service_type == "studio":
            if self._studio_token is None:
                self.authenticate_studio()
            request_header["Authorization"] = "Bearer {}".format(self._studio_token)

        return request_header

    # end method definition

    def do_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
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
                    "Sending %s request ->\nurl: %s\nheaders: %s\ndata: %s\njson: %s\nfiles: %s\ntimeout: %s",
                    method,
                    url,
                    json.dumps(headers, indent=2),
                    json.dumps(data, indent=2),
                    json.dumps(json_data, indent=2),
                    files,
                    timeout,
                )

                response = requests.request(
                    method=method,
                    url=url,
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
                    self.authenticate_chat()
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

    def exist_result_item(
        self,
        response: dict,
        key: str,
        value: str,
    ) -> bool:
        """Check existence of key / value pair in the response properties of an Aviator Studio call.

        There are two types of Aviator Studio responses. The /studio/v1/api seems to deliver
        plain lists while the /studio/v1 [non-api] seems to be be a dictionary with an embedded
        "results" list. This method handles both cases.

        Args:
            response (dict):
                REST response from an Aviator Studio REST call.
            key (str):
                The property name (key).
            value (str):
                The value to find in the item with the matching key.

        Returns:
            bool:
                True if the value was found, False otherwise.

        """

        if not response:
            return False

        # The lower level model REST APIs return directly a list.
        # We want to handle both cases:
        results = response if isinstance(response, list) else response.get("results", [])

        return any(key in result and result[key] == value for result in results)

    # end method definition

    def authenticate_chat(self) -> str:
        """Authenticate for Chat service at Content Aviator / CSAI.

        Returns:
            str | None:
                Authentication token or None if the authentication fails.

        """

        if self.otcs_object is None:
            msg = "OTCS Object is not defined, authentication failed."
            raise AttributeError(msg)

        token = self.otcs_object.otcs_ticket() or self.otcs_object.authenticate()

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

    def authenticate_embed(self) -> str | None:
        """Authenticate as embedding service at Content Aviator / CSAI.

        Returns:
            str | None:
                Authentication token or None if the authentication fails.

        """

        url = self.config()["otdsUrl"] + "/otdsws/login"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.config()["clientId"],
            "client_secret": self.config()["clientSecret"],
        }

        result = self.do_request(url=url, method="Post", data=data)

        if result:
            self._embed_token = result["access_token"]
            return self._embed_token
        else:
            self.logger.error(
                "Authentication failed with client ID -> '%s' against -> %s", self.config()["clientId"], url
            )
            return None

    # end method definition

    def authenticate_studio(self) -> str | None:
        """Authenticate at Aviator Studio.

        Returns:
            str | None:
                Authentication token or None if the authentication fails.

        """

        url = self.config()["otdsUrl"] + "/otdsws/oauth2/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.config()["clientId"],
            "client_secret": self.config()["clientSecret"],
        }

        result = self.do_request(url=url, method="Post", data=data)

        if result:
            self._studio_token = result["access_token"]
            return self._studio_token
        else:
            self.logger.error(
                "Authentication failed with client ID -> '%s' against -> %s", self.config()["clientId"], url
            )
            return None

    # end method definition

    def chat(self, context: str | None, messages: list, where: list | None = None, service_type: str = "chat") -> dict:
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
                Determines if Aviator Studio, OTCM Chat or Embedding API is used for the Authentication header.

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
            # "synonyms": self.config()["synonyms"],
            # "inlineCitation": self.config()["inlineCitation"],
        }

        if where:
            chat_data["where"] = where

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=chat_data,
            timeout=None,
            failure_message="Failed to chat with Content Aviator",
        )

    # end method definition

    def context(
        self, query: str, document_ids: list, workspace_ids: list, threshold: float = 0.5, num_results: int = 10
    ) -> dict:
        """Get semantic context for a given query string.

        Search requests are meant to be called as end-users. This should involve
        passing the end-user's access token via the Authorization HTTP header.
        The chat service use OTDS's token endpoint to ensure that the token is valid.

        Args:
            query (str):
                The query.
            document_ids (list):
                List of documents (IDs) to use as scope for the query.
            workspace_ids (list):
                List of workspaces (IDs) to use as scope for the query.
            threshold (float):
                Minimum similarity score to accept a document. A value like 0.7 means
                only bring back documents that are at least 70% similar.
            num_results (int):
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

        # Validations:
        # if not workspace_ids and not document_ids:
        #     self.logger.error("Either workspace ID(s) or document ID(s) need to be provided!")
        #     return None

        request_url = self.config()["contextUrl"]
        request_header = self.request_header(service_type="studio")

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
            failure_message="Failed to to do a semantic search with query -> '{}' !".format(query),
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

        """

        # Validations:
        if operation not in ["add", "update", "delete"]:
            self.logger.error("Illegal embed operation -> '%s'!", operation)
            return None
        if operation != "delete" and not content:
            self.logger.error("Add or update operation require content to embed!")
            return None

        request_url = self.config()["embedUrl"]
        request_header = self.request_header(service_type="embed")

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

    def direct_embed(
        self,
        content: list[str] | None = None,
        options: dict | None = None,
    ) -> dict | None:
        """Direct embed a given a list of strings. This is an Aviator Studio endpoint.

        Args:
            content (list[str] | None):
                Content to be embedded. This is a list of strings.
            options (dict | None):
                Optional parameters. Supported parameters (keys):
                * embeddingType (str) - e.g. "openai"
                * model (str) - e.g. "text-embedding-ada-002"
                * baseUrl (str) - e.g. "https://api.openai.com/v1"

        Returns:
            dict | None:
                REST API response or None in case of an error.

        Example:
        {
            'vectors': [
                [-0.04728065803647041, -0.006598987616598606, ...],
                [...]
            ]
        }

        """

        request_url = self.config()["directEmbedUrl"]
        request_header = self.request_header(service_type="studio")

        embed_data = {
            "content": content,
        }
        if options:
            embed_data["options"] = options

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=embed_data,
            timeout=None,
            failure_message="Failed to embed content",
        )

    # end method definition

    def get_graphs(self) -> list | None:
        """Get all graphs.

        Returns:
            list | None:
                A list of all graphs.

        Example:
        [
            {
                'id': '60fa6f74-a0a6-4f95-abf4-80a3ae19913c',
                'name': 'supervisor',
                'description': None,
                'attributes': None,
                'createdAt': '2025-07-01T09:06:28.123Z',
                'updatedAt': '2025-07-01T09:06:28.123Z',
                'tenantId': '010bae82-7b31-4e52-9db4-00bde19aa398'
            },
            {
                'id': 'f287ef5e-0acf-47cf-91cb-64b3195ceeb8',
                'name': 'breakdown',
                'description': None,
                'attributes': None,
                'createdAt': '2025-07-01T09:06:28.123Z',
                'updatedAt': '2025-07-01T09:06:28.123Z',
                'tenantId': '010bae82-7b31-4e52-9db4-00bde19aa398'
            },
            {
                'id': '378a6369-6f78-4ccc-a1f1-8b070973be24',
                'name': 'root',
                'description': None,
                'attributes': None,
                'createdAt': '2025-07-01T09:06:28.123Z',
                'updatedAt': '2025-07-01T09:06:28.123Z',
                'tenantId': '010bae82-7b31-4e52-9db4-00bde19aa398'
            },
            {
                'id': '6925e805-eaea-4054-a07f-e3e48c7bab15',
                'name': 'answer',
                'description': None,
                'attributes': None,
                'createdAt': '2025-07-01T09:06:28.123Z',
                'updatedAt': '2025-07-01T09:06:28.123Z',
                'tenantId': '010bae82-7b31-4e52-9db4-00bde19aa398'
            }
        ]

        """

        request_url = self.config()["studioGraphsUrl"]
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed get graphs",
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_graphs_iterator(self) -> iter:
        """Get an iterator object that can be used to traverse graphs.

        Returns:
            iter:
                A generator yielding one graph per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One graph at a time.

        """

        graphs: list = self.get_graphs()

        yield from graphs

    # end method definition

    def get_graph(
        self, graph_id: str | None = None, graph_name: str | None = None, show_error: bool = False
    ) -> dict | None:
        """Get a graph by its ID or by its name.

        Args:
            graph_id (str | None, optional):
                The ID of the graph to retrieve the nodes for.
            graph_name (str | None, optional):
                Alternatively the name of the graph to retrieve the nodes for.
            show_error (bool, optional):
                Whether to show error messages in case of failure. Defaults to True.

        Returns:
            dict | None:
                Graph data or none in case of an error.

        Example:
        {
            'id': 'a245ddcb-2df0-465a-abab-b21222245ba9',
            'name': 'supervisor',
            'description': None,
            'attributes': None,
            'createdAt': '2025-07-01T16:51:56.703Z',
            'updatedAt': '2025-07-01T16:51:56.703Z',
            'tenantId': '05f43f12-5865-46cd-8954-1af3dc575e88'
        }

        """

        if not graph_name and not graph_id:
            self.logger.error("Cannot get graph. Neither the graph ID nor the graph name are provided!")
            return None

        # If we only have the graph name but not the graph ID we lookup the ID first:
        if not graph_id:
            graphs = self.get_graphs()

            if graphs is None:
                return None

            graph = next((g for g in graphs if g["name"] == graph_name), None)

            if graph is None:
                if show_error:
                    self.logger.error("Graph -> '%s' not found!", graph_name)
                return None

            graph_id = graph["id"]

        request_url = self.config()["studioGraphsUrl"] + "/" + graph_id
        request_header = self.request_header(service_type="studio")

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed get graphs",
            show_error=show_error,
        )

    # end method definition

    def get_graph_nodes(
        self,
        graph_id: str | None = None,
        graph_name: str | None = None,
        limit: int = 100,
        offset: int = 0,
        retry_forever: bool = False,
        show_error: bool = True,
    ) -> list | None:
        """Get all nodes of a graph.

        This method supports either the graph ID or the graph name as input.

        Args:
            graph_id (str | None, optional):
                The ID of the graph to retrieve the nodes for.
            graph_name (str | None, optional):
                Alternatively the name of the graph to retrieve the nodes for.
            limit (int, optional):
                Maximum number of nodes to retrieve. Defaults to 100.
            offset (int, optional):
                Offset for pagination. Defaults to 0.
            retry_forever (bool, optional):
                Whether to wait forever without timeout. Defaults to False.
            show_error (bool, optional):
                Whether to show error messages in case of failure. Defaults to True.

        Returns:
            list | None:
                A list of all nodes of the graph.

        Example:
        [
            {
                'id': '1b99d09f-9e36-4da9-8fe0-8ebe0652fef3',
                'name': 'decision',
                'description': None,
                'discriminator': 1,
                'createdAt': '2025-07-01T09:06:28.140Z',
                'updatedAt': '2025-07-01T09:06:28.140Z',
                'version': 0,
                'status': 0,
                'graphId': '60fa6f74-a0a6-4f95-abf4-80a3ae19913c',
                'attributes': {
                    'studio': 'routerAgent'
                },
                'klassId': '20470453-2179-4392-aa0e-bc46ae3f3e80'
            }
        ]

        """

        if not graph_name and not graph_id:
            self.logger.error("Cannot get graph nodes. Neither the graph ID nor the graph name are provided!")
            return None

        # If we only have the graph name but not the graph ID we lookup the ID first:
        if not graph_id:
            graphs = self.get_graphs()

            if graphs is None:
                return None

            graph = next((g for g in graphs if g["name"] == graph_name), None)

            if graph is None:
                if show_error:
                    self.logger.error("Graph -> '%s' not found!", graph_name)
                return None

            graph_id = graph["id"]

        request_url = self.config()["studioGraphsUrl"] + "/" + graph_id + f"/nodes?limit={limit}&offset={offset}"
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed get list of graph nodes!",
            retry_forever=retry_forever,
            show_error=show_error,
        )

        if response is None:
            return None

        response = [graph for graph in response.get("results", []) if graph["graphId"] == graph_id]

        return response

    # end method definition

    def get_graph_nodes_iterator(
        self,
        graph_id: str | None = None,
        graph_name: str | None = None,
        limit: int = 100,
    ) -> iter:
        """Get an iterator object that can be used to traverse graph nodes.

        Args:
            graph_id (str | None, optional):
                The ID of the graph to retrieve the nodes for.
            graph_name (str | None, optional):
                Alternatively the name of the graph to retrieve the nodes for.
            limit (int, optional):
                Maximum number of nodes to retrieve with one REST call.
                Defaults to 100.

        Returns:
            iter:
                A generator yielding one node per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One node at a time.

        """

        offset = 0

        while True:
            nodes: list = self.get_graph_nodes(graph_id=graph_id, graph_name=graph_name, limit=limit, offset=offset)
            if nodes is None:
                return
            if len(nodes) == 0:
                return

            nodes = [node for node in nodes if node["graphId"] == graph_id]

            yield from nodes
            offset += limit

    # end method definition

    def get_graph_edges(
        self,
        graph_id: str | None = None,
        graph_name: str | None = None,
        limit: int = 100,
        offset: int = 0,
        retry_forever: bool = False,
        show_error: bool = True,
    ) -> list | None:
        """Get all edges of a graph.

        Args:
            graph_id (str | None, optional):
                The ID of the graph to retrieve the nodes for.
            graph_name (str | None, optional):
                Alternatively the name of the graph to retrieve the nodes for.
            limit (int, optional):
                Maximum number of edges to retrieve. Defaults to 100.
            offset (int, optional):
                Offset for pagination. Defaults to 0.
            retry_forever (bool, optional):
                Whether to wait forever without timeout. Defaults to False.
            show_error (bool, optional):
                Whether to show error messages in case of failure. Defaults to True.

        Returns:
            list | None:
                A list of all edges of the graph.

        Example:
        [
            {
                'id': '420610ae-68d0-47d2-9807-6e5a5f75a02d',
                'sourceId': '8cec788a-23eb-4480-a004-1f3c7edd1054',
                'targetId': '233db9e1-1f5a-4fb6-8f70-fca46199c224',
                'type': 0,
                'graphId': '60fa6f74-a0a6-4f95-abf4-80a3ae19913c',
                'createdAt': '2025-07-01T09:06:28.192Z',
                'updatedAt': '2025-07-01T09:06:28.192Z',
                'version': 0,
                'status': 0,
                'attributes': None
            }
        ]

        """

        if not graph_name and not graph_id:
            self.logger.error("Cannot get graph edges. Neither the graph ID nor the graph name are provided!")
            return None

        # If we only have the graph name but not the graph ID we lookup the ID first:
        if not graph_id:
            graphs = self.get_graphs()

            if graphs is None:
                return None

            graph = next((g for g in graphs if g["name"] == graph_name), None)

            if graph is None:
                if show_error:
                    self.logger.error("Graph -> '%s' not found!", graph_name)
                return None

            graph_id = graph["id"]

        request_url = self.config()["studioGraphsUrl"] + "/" + graph_id + f"/edges?limit={limit}&offset={offset}"
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed get list of graph edges!",
            retry_forever=retry_forever,
            show_error=show_error,
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_graph_edges_iterator(
        self, graph_id: str | None = None, graph_name: str | None = None, limit: int = 100
    ) -> iter:
        """Get an iterator object that can be used to traverse graph edges.

        Args:
            graph_id (str | None, optional):
                The ID of the graph to retrieve the nodes for.
            graph_name (str | None, optional):
                Alternatively the name of the graph to retrieve the nodes for.
            limit (int, optional):
                Maximum number of nodes to retrieve with one REST call.
                Defaults to 100.

        Returns:
            iter:
                A generator yielding one edge per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One edge at a time.

        """

        offset = 0

        while True:
            edges: list = self.get_graph_edges(graph_id=graph_id, graph_name=graph_name, limit=limit, offset=offset)
            if edges is None:
                return
            if len(edges) == 0:
                return

            # filter edges with different graph id
            edges = [edge for edge in edges if edge["graphId"] == graph_id]

            yield from edges
            offset += limit

    # end method definition

    def get_model_types(self) -> list:
        """Get a list of all model types. Hardcoded.

        Returns:
            list:
                Model types.

        """

        return ["tenants", "graphs", "nodes", "edges", "actions", "tools", "prompts", "rules", "klasses"]

    # end method definition

    def import_configuration(self, json_data: dict | None = None) -> bool:
        """Import Aviator Studio default configuration.

        Returns:
            bool:
                True = success, False = error.

        """

        request_url = self.config()["studioImportUrl"]
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=json_data,
            timeout=None,
            show_error=True,
            parse_request_response=False,
            failure_message="Failed to load default Aviator Studio configuration!",
        )

        if not response or response.text != "Accepted":
            self.logger.error("Failed to import Aviator Studio configuration!")
            return False

        self.logger.info("Successfully imported Aviator Studio configuration.")

        return True

    # end method definition

    def export_configuration(self, show_ids: bool = False) -> dict | None:
        """Export the current Aviator Studio configuration.

        Args:
            show_ids(bool, optional):
                Determines if the ids of the database records will included in the export.

        Returns:
            dict | None:
                List of tenants or None in case the request failed.

        Example:
        {
            'default': {
                'id': '8302ca78-a6e1-416d-a93c-39aab189d943',
                'graphs': {
                    'supervisor': {
                        'id': 'abc7436a-33bf-4775-81f6-916961dbb9a0',
                        'nodes': {...},
                        'edges': [...]
                    },
                    'breakdown': {
                        'id': 'ea748d81-554f-4638-9789-fd905c8e680f',
                        'nodes': {...},
                        'edges': [...]
                    },
                    'root': {
                        'id': 'faf54d3f-b6d7-4954-b222-12f99fd9eb51',
                        'nodes': {...},
                        'edges': [...]
                    },
                    'answer': {
                        'id': 'eb563724-4fae-4c82-b24b-955ba57f827c',
                        'nodes': {...},
                        'edges': [...]
                    },
                    'directChat': {
                        'id': '702176fa-1701-43d4-84eb-d7628f1f29f7',
                        'nodes': {...},
                        'edges': [...]
                    }
                },
                'prompts': {
                    'cat_prompt': {
                        'id': '3c96c5e3-dfa2-4aa8-9ce3-2080e0726241',
                        'type': 'system',
                        'template': 'Your name is Cat Aviator and you are an AI Assitant that answers questions and always ends answers with jokes about cats.',
                        'description': 'This is a Cat prompt',
                        'attributes': {},
                        'overrides': [...]
                    },
                    'breakdown_system': {
                        'id': 'db797917-4657-48a8-bcf3-fb4a3cd9a0d3',
                        'type': 'system',
                        'template': "Given a user message, break it down into separate messages. Guidelines: ..."
                    },
                    'chart_prompt': {
                        'id': 'fa9ff09f-6294-4265-8971-75324024b9b5',
                        'type': 'system',
                        'template': 'You are Aviator, an expert in producing data visualizations using Vega-Lite. Your primary task is ...',
                    },
                    'agent_route_branch_query': {
                        'id': '3a117045-191d-4603-84e7-4ee6b0ba7bb1',
                        'type': 'message',
                        'template': 'Given the conversation above, pick the right agent to perform the task. Select one of: {options}'
                    },
                    'general_system': {
                        'id': '8f499e25-d07a-4fc0-bb9c-b5392825f7c8',
                        'type': 'system',
                        'template': "Your name is Aviator and you are a friendly chatbot assisting users with their queries ...',
                    },
                    'breakdown_message': {
                        'id': 'c2498919-9cba-44f4-aecc-add09a6e94ad',
                        'type': 'message',
                        'template': 'Remember, only respond with a JSON object. E.g.  {{"input": ["message1", "message2"]}}'
                    },
                    'summarize': {
                        'id': '4fe7d77d-a28d-489f-83c8-fa514745b8d0',
                        'type': 'message',
                        'template': 'The CONTEXT contains text of tool calls, arguments and their responses in the format...',
                    },
                    'email_system': {
                        'id': '0e8e8eaf-dcce-4b35-b0ae-898bd1ba662a',
                        'type': 'system',
                        'template': 'Your name is Aviator and you are a friendly chatbot assisting customers ...',
                    },
                    'llm_compiler_system': {
                        'id': 'd0ed1d43-b212-4025-bfff-021d43970b93',
                        'type': 'system',
                        'template': 'Given a user query, create a plan to solve it ...',
                        'attributes': {...}
                    },
                    'compare_documents_message': {
                        'id': 'ccc6b435-f24b-4396-a196-6cd771f486c5',
                        'type': 'message',
                        'template': 'You are tasked with a comparative analysis of the documents...',
                    },
                    'agent_route_branch_system': {
                        'id': '55a573dc-9e83-4901-88b9-f81d18c35ffb',
                        'type': 'system',
                        'template': 'Your job is to decide which agent to run based on the information provided to you. ...',
                    },
                    'check_answer_prompt': {},
                    'validator_branch_system': {},
                    'search_query_system': {},
                    'search_query_message': {},
                    'general_message': {},
                    'cite_references': {},
                    ...
                'classes': {...},
                'rules': {...},
                'llmModels': {
                    'qwen3:8b': {
                        'id': 'abbbddf4-2850-4fbb-9b49-b7354b348785',
                        'family': 'qwen3',
                        'version': 'qwen3:8b',
                        'attributes': {
                            'topK': 40,
                            'topP': 0.8,
                            'cache': False,
                            'baseUrl': 'http://localhost:11434',
                            'maxTokens': 8000,
                            'maxRetries': 2,
                            'temperature': 0.2,
                            'llmIntegration': 'ollama'
                        }
                    }
                }
            },
            ...
        }

        """

        query = {}
        if show_ids:
            query["showIds"] = "true" if show_ids else "false"

        if query:
            encoded_query = urllib.parse.urlencode(query=query, doseq=True)
            request_url = self.config()["studioExportUrl"] + "?{}".format(encoded_query)
        else:
            request_url = self.config()["studioExportUrl"]

        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            parse_request_response=True,
            failure_message="Failed to export Aviator Studio configuration!",
        )

        return response

    # end method definition

    def get_scratchpad(self, chat_id: str) -> dict | None:
        """Get the current scratchpad content.

        Args:
            chat_id (str):
                The chat ID.

        Returns:
            dict | None:
                Scratchpad content or None in case of an error.

        Example:
        {
            'id': 'default',
            'content': 'This is some scratchpad content.'
        }

        """

        request_url = self.config()["scratchPadUrl"] + "/" + str(chat_id)
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed to get scratchpad content!",
        )

        return response

    # end method definition

    def get_tenants(self) -> list | None:
        """Get list of Aviator Studio tenants.

        Returns:
            dict | None:
                List of tenants or None in case the request failed.

        Example:
        [
            {
                'id': 'edfb5af5-eb82-4867-bbea-fb7e3cba74f5',
                'externalId': 'default',
                'createdAt': '2025-08-29T22:59:26.579Z',
                'updatedAt': '2025-08-29T22:59:26.579Z'
            }
        ]

        """

        request_url = self.config()["studioTenantsUrl"]
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed to get list of tenants!",
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_llms(self, attributes: str | None = None) -> dict | None:
        """Get a list of configured LLMs in Aviator Studio.

        Args:
            attributes (str | None, optional):
                A comma-separated list of attribute fields (in a string).
                The default is None. In this case all fields are returned.
                Example: "name,id,tenantId,family,version,attributes"

        Returns:
            dict | None:
                List of tenants or None in case the request failed.

        Example:
        {
            'results': [
                {
                    'id': 'abbbddf4-2850-4fbb-9b49-b7354b348785',
                    'tenantId': '8302ca78-a6e1-416d-a93c-39aab189d943',
                    'family': 'qwen3',
                    'version': 'qwen3:8b',
                    'name': 'qwen3:8b',
                    'attributes': {
                        'topK': 40,
                        'topP': 0.8,
                        'cache': False,
                        'baseUrl': 'http://localhost:11434',
                        'maxTokens': 8000,
                        'maxRetries': 2,
                        'temperature': 0.2,
                        'llmIntegration': 'ollama'
                    },
                    'createdAt': '2025-08-30T15:30:03.727Z',
                    'updatedAt': '2025-08-30T15:30:03.727Z',
                    'status': 0
                },
                ...
            ],
            _links': {
                'self': {'href': '/'}
            }
        }

        """

        query = {}
        if attributes:
            query["attributes"] = attributes

        if query:
            encoded_query = urllib.parse.urlencode(query=query, doseq=True)
            request_url = self.config()["studioLLModelsUrl"] + "?{}".format(encoded_query)
        else:
            request_url = self.config()["studioLLModelsUrl"]

        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed to get configured LLMs!",
        )

        return response

    # end method definition

    def add_llm(
        self,
        name: str,
        family: str,
        version: str,
        tenant_id: str,
        status: int = 0,
        attributes: dict | None = None,
        llm_integration: str = "",
        base_url: str = "",
    ) -> dict | None:
        """Add an LLM to Aviator Studio.

        Args:
            name (str):
                The name of the model, e.g. ""gemini-2.5-flash-001".
            family (str):
                The model family name, e.g. "gemini".
            version (str):
                The model version (normally the same as name)
            tenant_id (str):
                The tenant ID. Should be retrieved with get_tenants() before.
            status (int, optional):
                0 = enabled
                1 = disabled
                2 = deleted
            attributes (dict | None, optional):
                The LLM attributes.
                * temperature (float)
                * maxTokens (int)
                * maxRetries (int)
                * topK (int)
                * topP (float)
                * cache (bool)
                * llmIntegration (str)
            llm_integration (str, optional):
                Name of the LLM integration
                * "vertex" (for Google)
                * "ollama" (for Ollama hosted models)
                * "localai" (for other locally running models)
                * "bedrock" (AWS)
                * "azure" (Microsoft)
            base_url (str, optional):
                Not required for Gemini. Should be "http://localhost:11434" for Ollama running locally.

        Returns:
            dict | None:
                List of tenants or None in case the request failed.

        Example:
        {
            'id': 'abbbddf4-2850-4fbb-9b49-b7354b348785',
            'name': 'qwen3:8b',
            'family': 'qwen3',
            'version': 'qwen3:8b',
            'tenantId': '8302ca78-a6e1-416d-a93c-39aab189d943',
            'status': 0,
            'attributes': {
                'topK': 40,
                'topP': 0.8,
                'cache': False,
                'baseUrl': 'http://localhost:11434',
                'maxTokens': 8000,
                'maxRetries': 2,
                'temperature': 0.2,
                'llmIntegration': 'ollama'
            },
            'updatedAt': '2025-08-30T15:30:03.727Z',
            'createdAt': '2025-08-30T15:30:03.727Z'
        }

        """

        if attributes is None:
            attributes = DEFAULT_LLM_ATTRIBUTES

        if llm_integration:
            attributes["llmIntegration"] = llm_integration
        if base_url:
            attributes["baseUrl"] = base_url

        request_url = self.config()["studioLLModelsUrl"]
        request_header = self.request_header(service_type="studio")
        request_data = {
            "name": name,
            "family": family,
            "version": version,
            "tenantId": tenant_id,
            "status": status,
            "attributes": attributes,
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=request_data,
            timeout=None,
            show_error=True,
            failure_message="Failed to add LLM -> '{}' to tenant ID -> '{}'!".format(name, tenant_id),
        )

        return response

    # end method definition

    def add_graph_node(
        self,
        graph_name: str,
        node_name: str,
        description: str = "",
        klass_name: str = "",
        type_id: int = 0,
        attributes: dict | None = None,
    ) -> dict | None:
        """Add a node to a specific graph.

        Args:
            graph_name (str):
                The name of the graph to add the node to.
            node_name (str):
                The name of the node to add.
            description (str, optional):
                An arbitrary description of the node. Defaults to "".
            klass_name (str, optional):
                The name of the klass to assign to the node. Defaults to "".
            type_id (int, optional):
                The type of the node. Defaults to 0.
            attributes (dict | None, optional):
                The node attributes.

        Returns:
            dict | None:
                The data of the created node.

        Example:
        {
            "createdAt": "2025-10-28T17:14:17.979Z",
            "updatedAt": "2025-10-28T17:14:17.979Z",
            "id": "e5aad457-06d4-4de1-91d3-35d45c11ff4b",
            "status": 0,
            "name": "otcmDocgenGraph",
            "description": "This is a test node added via OTCA API",
            "graphId": "6bd500a0-4d2e-4c2b-b6e0-ffeff5e4db1f",
            "discriminator": 0,
            "version": 1,
            "klassId": "730c7008-9401-4549-93b6-f6aab3198529",
            "attributes": { "name": "otcm_docgen" }
        }

        """

        # Get graph ID by name
        graph = self.get_graph(graph_name=graph_name)

        if graph is None:
            return None

        graph_id = graph["id"]

        klasses = self.get_klasses()
        klass_id = next((k["id"] for k in klasses if k["name"] == klass_name), None)

        node_data = {
            "type": type_id,
            "name": node_name,
            "klassId": klass_id,
            "description": description,
            "attributes": attributes or {},
        }

        request_url = self.config()["studioGraphsUrl"] + "/" + graph_id + "/nodes"
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=node_data,
            timeout=None,
            show_error=True,
            failure_message="Failed to add node to graph -> '{}'!".format(graph_name),
        )

        return response

    # end method definition

    def add_graph_edge(
        self,
        graph_name: str,
        source_node_name: str,
        target_node_name: str,
        type_id: int = 0,
        attributes: dict | None = None,
    ) -> dict | None:
        """Add an edge to a specific graph.

        Args:
            graph_name (str):
                The name of the graph to add the edge to.
            source_node_name (str):
                The name of the source node.
            target_node_name (str):
                The name of the target node.
            type_id (int, optional):
                The type of the edge. Defaults to 0.
            attributes (dict | None, optional):
                The edge attributes.

        Returns:
            dict | None:
                The data of the created edge.

        Example:
        {
            "createdAt": "2025-10-28T17:38:32.262Z",
            "updatedAt": "2025-10-28T17:38:32.262Z",
            "id": "59a30a6d-350f-4332-979c-384136e1ac99",
            "status": 0,
            "sourceId": "06e09a75-8f5e-4bb4-930f-be2bef3c2aba",
            "targetId": "e464c402-f6dc-4868-892b-cbcd85154202",
            "type": 0,
            "attributes": {},
            "graphId": "6bd500a0-4d2e-4c2b-b6e0-ffeff5e4db1f",
            "version": 1
        }

        """

        # Get graph ID by name
        graph = self.get_graph(graph_name=graph_name)

        if graph is None:
            return None

        graph_id = graph["id"]

        source_node = self.get_models(model_type="nodes", where={"name": source_node_name, "graphId": graph_id})
        target_node = self.get_models(model_type="nodes", where={"name": target_node_name, "graphId": graph_id})

        if not source_node or not target_node:
            self.logger.error(
                "Could not find source node -> '%s' and target node -> '%s' in graph -> '%s'!",
                source_node_name,
                target_node_name,
                graph_name,
            )
            return None

        source_node = source_node[0]
        target_node = target_node[0]

        # Check for existing edge with same source, target, type, and attributes
        existing_edges = [
            e
            for e in self.get_graph_edges_iterator(graph_id=graph_id)
            if e["sourceId"] == source_node["id"] and e["targetId"] == target_node["id"]
        ]

        # Check if edge already exists in graph:
        for target_edge in existing_edges:
            if target_edge.get("attributes") == (attributes or {}) and target_edge.get("type") == type_id:
                self.logger.info(
                    "Edge from node -> '%s' to node -> '%s' with attributes (%s) and type (%s) already exists in graph -> '%s'. Skipping creation.",
                    source_node_name,
                    target_node_name,
                    json.dumps(attributes),
                    type_id,
                    graph_name,
                )
                return target_edge

        edge_data = {
            "sourceId": source_node["id"],
            "targetId": target_node["id"],
            "type": type_id,
            "attributes": attributes or {},
        }
        request_url = self.config()["studioGraphsUrl"] + "/" + graph_id + "/edges"
        request_header = self.request_header(service_type="studio")
        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=edge_data,
            timeout=None,
            show_error=True,
            failure_message="Failed to add edge in graph -> '{}' from node -> '{}' to node -> '{}' !".format(
                graph_name, source_node_name, target_node_name
            ),
        )

        return response

    # end method definition

    def direct_chat(
        self,
        llm_model: str | None = None,
        messages: list | None = None,
    ) -> dict | None:
        r"""Chat with a LLM directly. This is bypassing the configured LangGraph completely.

        Args:
            llm_model (str | None, optional):
                The name of the model to use. If None then the default model is used.
            messages (list | None, optional):
                List of messages including conversation history. Each list element is
                a dictionary with two keys: "author" and "content".
                Example: [{"author": "user", "content": "What is the recommended fridge temperature?"}]

        Returns:
            dict | None:
                The data of the created prompt. This includes the prompt ID and the prompt version.

        Example:
        {
            'result': "The recommended temperature for a refrigerator is below 40°F (4°C). The ideal temperature range is between 37°F (3°C) and 40°F (4°C). "
        }

        """

        request_url = self.config()["directChatUrl"]
        request_header = self.request_header(service_type="studio")
        request_data = {
            "messages": messages,
        }
        if llm_model is not None:
            request_data["llmModelName"] = llm_model

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=request_data,
            timeout=None,
            show_error=True,
            failure_message="Failed to chat with LLM -> '{}'!".format(
                llm_model if llm_model is not None else "<default model>"
            ),
        )

        return response

    # end method definition

    def get_models(self, model_type: str, limit: int = 100, offset: int = 0, where: dict | None = None) -> list | None:
        """Get all model details by type.

        Args:
            model_type (str):
                The type of the model. Possible model types:
                * tenants
                * graphs
                * nodes
                * edges
                * actions
                * tools
                * prompts
                * rules
                * klasses
            limit (int, optional):
                The maximum number of models to return. Default is 100.
            offset (int, optional):
                The number of models to skip before starting to collect the result set. Default is 0
            where (dict | None, optional):
                A dictionary with filter conditions.


        Returns:
            list | None:
                A list of all models of a given type.

        """

        request_url = self.config()["studioModelsUrl"] + "/" + model_type + f"?limit={limit}&offset={offset}"

        if where:
            where_json = json.dumps(where)
            where_encoded = urllib.parse.quote(where_json)
            request_url += f"&where={where_encoded}"

        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed to get list of models",
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_models_iterator(self, model_type: str, where: dict | None = None) -> iter:
        """Get an iterator object that can be used to traverse models.

        Args:
            model_type (str):
                The type of the model. Possible model types:
                * tenants
                * graphs
                * nodes
                * edges
                * actions
                * tools
                * prompts
                * rules
                * klasses
            where (dict | None, optional):
                A dictionary with filter conditions.

        Returns:
            iter:
                A generator yielding one model per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One edge at a time.

        """

        limit = 100
        offset = 0

        while True:
            models: list = self.get_models(model_type=model_type, limit=limit, offset=offset, where=where)
            if models is None:
                return
            if len(models) == 0:
                return

            yield from models
            offset += limit

    # end method definition

    def get_model(self, model_type: str, model_id: str) -> dict | None:
        """Get a specific model based on its type and ID.

        Args:
            model_type (str):
                The type of the model. Possible model types:
                * tenants
                * graphs
                * nodes
                * edges
                * actions
                * tools
                * prompts
                * rules
                * klasses
            model_id (str):
                The ID of the model.

        Returns:
            dict | None:
                The model data.

        """

        request_url = self.config()["studioModelsUrl"] + "/" + model_type + "/" + model_id
        request_header = self.request_header(service_type="studio")

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed to get models with type -> '{}' and ID -> {}!".format(model_type, model_id),
        )

    # end method definition

    def get_model_by_type_and_name(self, model_type: str, name: str) -> dict | None:
        """Get model details by model type and name.

        Args:
            model_type (str):
                The type of the model.
            name (str):
                The name of the model.

        Returns:
            dict:
                Model details or None in case of an error.

        """

        models = self.get_models_iterator(model_type=model_type, where={"name": name})
        if models:
            return next((model for model in models if model["name"] == name), None)

        return None

    # end method definition

    # end method definition

    def delete_model(self, model_type: str, model_id: str) -> dict | None:
        """Delete a model by type and id.

        Args:
            model_type (str):
                The type of the model.
            model_id (str):
                The model name.

        Returns:
            dict | None:
                Dict with the model details

        """

        self.logger.info("Deleting existing model -> '%s' (%s)", model_type, model_id)

        request_header = self.request_header(service_type="studio")
        request_url = self.config()["studioModelsUrl"] + "/" + model_type + "/" + model_id
        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed to delete model -> '{}' ({})!".format(model_type, model_id),
        )

    # end method definition

    def update_model(self, model_type: str, model_id: str, request_body: dict) -> dict | None:
        """Update a model with a given type and ID.

        Args:
            model_type (str):
                The type of the model.
            model_id (str):
                The ID of the model.
            request_body (dict):
                Data to update the model.

        Returns:
            dict | None:
                Dict with the model details or None in case of an error.

        """

        self.logger.debug("Updating existing model -> '%s' (%s)", model_type, model_id)

        request_header = self.request_header(service_type="studio")
        request_url = self.config()["studioModelsUrl"] + "/" + model_type + "/" + model_id
        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            json_data=request_body,
            timeout=None,
            show_error=True,
            failure_message="Failed to update model -> '{}' ({}).".format(model_type, model_id),
        )

    # end method definition

    def get_tools(self) -> list | None:
        """Get all tools.

        Returns:
            list:
                A list of all tools.

        Example:
        [
            {
                'id': '305353d8-7391-497e-9f3f-8a1fe11ceac0',
                'attributes': {
                    'conditions': [{'messageLength': 2}],
                    'maxHistory': -1,
                    'showInContext': True
                },
                'klassId': 'b033b1d5-8182-4883-ba8a-16f0048b01b0',
                'name': 'rephrase_search',
                'description': 'Used for creating a standalone search query for retrieving documents. Input should be a dependent user message',
                'discriminator': 0,
                'createdAt': '2025-07-01T22:57:13.135Z',
                'updatedAt': '2025-07-01T22:57:13.135Z',
                'version': 0,
                'status': 0,
                'graphId': '93897862-d999-4fe0-82fc-3f9d03474545'
            }
        ]

        """

        return self.get_models(model_type="tools")

    # end method definition

    def get_tools_iterator(self) -> iter:
        """Get an iterator object that can be used to traverse tools.

        Returns:
            iter:
                A generator yielding one tool per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One tool at a time.

        """

        tools: list = self.get_models(model_type="tools")

        yield from tools

    # end method definition

    def get_tool(self, tool_id: str) -> dict | None:
        r"""Get a tool by its ID.

        Args:
            tool_id (str):
                The ID of the tool.

        Returns:
            dict | None:
                Tool data or none in case of an error.

        Example:
        {
            'id': '49e230ef-024a-4dd8-beeb-70210cec0564',
            'attributes': {'APISchema': {...}},
            'klassId': '275843d9-c39f-43e2-ad00-b02ac42b5dd6',
            'name': 'otcm_workspace_agent_lookup_workspace',
            'description': 'Lookup a workspace based on its type and a value of one of the workspace attributes.\n\nUse this tool if the workspace name is _not_ specified but the user asks for a specific\nworkspace attribute value like cities, products, or other attributes.\n\nReturn the workspace data if it is found. If it is not found confirm with the user if the workspace should be created or not.\nIf it should be created call the tool: otcm_workspace_agent_create_workspace',
            'discriminator': 0,
            'createdAt': '2025-07-01T22:57:13.535Z',
            'updatedAt': '2025-07-01T22:57:13.535Z',
            'version': 0,
            'status': 0,
            'graphId': '93897862-d999-4fe0-82fc-3f9d03474545'
        }

        """

        tool = self.get_model(model_type="tools", model_id=tool_id)

        return tool

    # end method definition

    def register_tool(
        self,
        request_body: dict,
    ) -> dict:
        r"""Register a Tool in Content Aviator.

        Requests are meant to be called as a service user. This would involve passing a service user's access token
        (token from a particular OAuth confidential client, using client credentials grant).

        Args:
            request_body (dict):
                Body for the request. Needs to look like:
                example:
                    {
                        "name": "tool name",
                        "description": "description of the tool",
                        "APISchema": {} # dict of the APISchema, compliant with openapi 3.0.0
                        "requestTemplate": {
                            "data": {
                                "context": {
                                    "where": "memory.input.where",
                                    "query": "memory.input.query"
                                }
                            },
                        },
                        "responseTemplate": {
                            'scratchpad': {
                                'item': {
                                    'input': {'where': 'response.context_update.where'}
                                }
                            },
                            "agents": ["retrieverAgent"],
                        }

        Returns:
            dict: Tool details or None in case of an error.

        Example:
            {
                'id': '27ce608f-41ea-4128-aff9-91facc66bcfa',
                'attributes': {
                    'APISchema': {
                        'openapi': '3.0.0',
                        'info': {
                            'title': 'otcm_workspace_agent_find_workspace',
                            'version': '0.0.0'
                        },
                        'servers': [{'url': 'http://customizer:8000'}],
                        'paths': {
                            '/agents/otcm_workspace_agent/find_workspace': {
                                'post': {
                                    'tags': [...],
                                    'summary': 'Find the markdown link to a workspace by workspace name and workspace type and display the link.',
                                    'description': 'Find a workspace by workspace name and workspace type.\n\nThe returned workspace is an OTCS workspace object. Show the markdown link in the chat response, sothat the user can click on it.',
                                    'operationId': 'otcm_workspace_agent_find_workspace_agents_otcm_workspace_agent_find_workspace_post',
                                    'requestBody': {...},
                                    'responses': {
                                        '200': {
                                            'description': 'Workspace found',
                                            'content': {
                                                'application/json': {
                                                    'schema': {'$ref': '#/components/schemas/WorkspaceModel'}
                                                }
                                            }
                                        },
                                        '403': {
                                            'description': 'Invalid credentials'
                                        },
                                        '404': {
                                            'description': 'Workspace not found'
                                        },
                                        '422': {
                                            'description': 'Validation Error',
                                            'content': {...}
                                        }
                                    },
                                    'security': [...]
                                }
                            }
                        },
                        'components': {
                            'schemas': {
                                'Body_otcm_workspace_agent_find_workspace_agents_otcm_workspace_agent_find_workspace_post': {
                                    'properties': {...},
                                    'type': 'object',
                                    'required': [...],
                                    'title': 'Body_otcm_workspace_agent_find_workspace_agents_otcm_workspace_agent_find_workspace_post'
                                },
                                'Context': {
                                    'properties': {...},
                                    'type': 'object',
                                    'required': [...],
                                    'title': 'Context',
                                    'description': 'Define Model that is used to provide static context information for tools.'
                                },
                                'HTTPValidationError': {
                                    'properties': {...},
                                    'type': 'object',
                                    'title': 'HTTPValidationError'
                                },
                                'ValidationError': {
                                    'properties': {...},
                                    'type': 'object',
                                    'required': [...],
                                    'title': 'ValidationError'
                                },
                                'WorkspaceModel': {
                                    'properties': {...},
                                    'type': 'object',
                                    'title': 'WorkspaceModel',
                                    'description': 'Defines Model for describing workspaces in OTCM (Opentext Content Management).\n\nTo display an instance of this model, please display the link.'
                                }
                            },
                            'securitySchemes': {...}
                        }
                    },
                    'showInContext': True,
                    'responseFormat': 'content_and_artifact',
                    'requestTemplate': {
                        'data': {
                            'context': {
                                'query': 'memory.input.query',
                                'where': 'memory.input.where'
                            }
                        }
                    },
                    'responseTemplate': {}
                },
                'klassId': '1d8dbd52-5dee-4645-841d-2889fac74b13',
                'name': 'otcm_workspace_agent_find_workspace',
                'description': 'Find a workspace by workspace name and workspace type.\n\nThe returned workspace is an OTCS workspace object. Show the markdown link in the chat response, sothat the user can click on it.',
                'discriminator': 0,
                'createdAt': '2025-07-09T12:35:26.464Z',
                'updatedAt': '2025-07-09T12:35:26.464Z',
                'version': 0,
                'status': 0,
                'graphId': '440aae89-8942-4bb0-8107-291227f8ad92'
            }

        """

        # Validations:
        for key in ["name", "description", "APISchema", "agents"]:
            if key not in request_body:
                self.logger.error("%s is missing in provided request body for AI tool registration!", key)
                return None

        # Check if the tool already exists and need to be updated only:
        self.logger.debug("Check if AI tool -> '%s' is already registered...", request_body["name"])
        model = self.get_model_by_type_and_name(model_type="nodes", name=request_body["name"])
        if model:
            self.logger.info("Updating existing AI tool -> '%s'...", request_body["name"])

            ## Update the values that are defined in the request body:
            if "description" in request_body:
                model["description"] = request_body["description"]

            for s in ["requestTemplate", "responseTemplate", "responseFormat", "APISchema"]:
                if s in request_body:
                    model["attributes"][s] = request_body[s]

            def set_required_false(obj: dict) -> None:
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if key == "required" and value is True:
                            obj[key] = False
                        else:
                            set_required_false(value)
                elif isinstance(obj, list):
                    for item in obj:
                        set_required_false(item)

            set_required_false(model["attributes"]["APISchema"])

            response = self.update_model(model_type="tools", model_id=model["id"], request_body=model)

        else:
            self.logger.info("Register AI tool -> '%s'...", request_body["name"])

            request_header = self.request_header(service_type="studio")
            request_url = self.config()["studioToolsUrl"]

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                json_data=request_body,
                timeout=None,
                show_error=True,
                failure_message="Failed to register AI tool -> '{}'!".format(request_body["name"]),
            )

        return response

    # end method definition

    def register_prompt(
        self,
        name: str,
        description: str,
        template: str,
        attributes: dict | None = None,
    ) -> dict:
        """Register an Agent in Content Aviator.

        Requests are meant to be called as a service user. This would involve passing a service user's access token
        (token from a particular OAuth confidential client, using client credentials grant).

        Args:
            name (str):
                The name of the prompt.
            description (str):
                A description of the prompt.
            template (str):
                The prompt template for the agent.
            attributes (dict | None, optional):
                Additional attributes for the prompt.

        Returns:
            dict | None:
                Prompt details or None in case of an error.

        Example:
            {
                "agentID": "d6406846-76f8-4cd4-ba29-d3a666e8ad7c",
                "name": "testagent"
            }

        """

        request_body = {
            "name": name,
            "description": description,
            "template": template,
            "attributes": attributes or {},
        }

        # Check if prompt already exists, then update it if any settings are changed:
        prompt = self.get_model_by_type_and_name(model_type="prompts", name=name)
        if prompt:
            # Check if any detail has changed so we need to update the prompt:
            update_required = False
            for k, v in request_body.items():
                if prompt.get(k) != v:
                    prompt[k] = v
                    update_required = True

            if update_required:
                self.logger.info("Updating existing AI prompt -> '%s'...", name)
                prompt = self.update_model(model_type="prompts", model_id=prompt["id"], request_body=prompt)

            return prompt
        # end if prompt:

        self.logger.info("Register new AI prompt -> '%s'...", name)

        request_header = self.request_header(service_type="studio")
        request_url = self.config()["studioPromptsUrl"]

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=request_body,
            timeout=None,
            show_error=True,
            failure_message="Failed to register AI prompt -> '{}'!".format(name),
        )

        return response

    # end method definition

    def register_agent(
        self,
        name: str,
        description: str,
        prompt_template: str,
        graph_name: str = "supervisor",
    ) -> dict | None:
        """Register an Agent in Content Aviator.

        Requests are meant to be called as a service user. This would involve passing a service user's access token
        (token from a particular OAuth confidential client, using client credentials grant).

        Args:
            name (str):
                The name of the agent.
            description (str):
                A description of the agent.
            prompt_template (str):
                The prompt template for the agent.
            graph_name (str, optional):
                The name of the graph to use. Defaults to "supervisor".

        Returns:
            dict:
                Agent details or None in case of an error.

        Example:
            {
                "agentID": "d6406846-76f8-4cd4-ba29-d3a666e8ad7c",
                "name": "testagent"
            }

        """

        prompt = self.register_prompt(
            name=name + "_prompt",
            description="Prompt for agent '{}'".format(name),
            template=prompt_template,
        )

        if prompt is None or "id" not in prompt:
            self.logger.error("Failed to create prompt for agent -> '%s'!", name)
            return None

        request_body = {
            "name": name,
            "description": description,
            "graph": graph_name,
            "tools": [],
            "promptTemplateID": prompt["id"],
        }

        # Check if agent already exists, then update it if any settings are changed:
        agent = self.get_model_by_type_and_name(model_type="nodes", name=name)
        if agent:
            # Check if any detail has changed so we need to update the prompt:
            update_required = False
            for k, v in request_body.items():
                if agent.get(k) != v:
                    agent[k] = v
                    update_required = True

            if update_required:
                self.logger.info("Updating existing AI agent -> '%s'...", name)
                agent = self.update_model(model_type="nodes", model_id=agent["id"], request_body=agent)

            return agent
        # end if agent:

        self.logger.info("Register new AI agent -> '%s'...", name)

        request_header = self.request_header(service_type="studio")
        request_url = self.config()["studioAgentsUrl"]

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=request_body,
            timeout=None,
            show_error=True,
            failure_message="Failed to register AI agent -> '{}'!".format(name),
        )
        return response

    # end method definition

    def get_rules(self) -> list | None:
        r"""Get all rules.

        Returns:
            list:
                A list of all rules.

        Example:
        [
            {
                'id': '4d089d1e-205d-4ff4-8128-7c2a83bd2462',
                'name': 'evaluateLastToolResult',
                'description': 'Equivalent of previous "toolResult" check. Evaluates the result of last tool executed and compares it with a given string. Returns `true` or `false`. This is the equivalent of \n ```const lastTool = memory.response.called[memory.response.called.length - 1];\nreturn lastTool?.result === (andConditions[condition]);```',
                'createdAt': '2025-07-01T16:51:56.703Z',
                'updatedAt': '2025-07-01T16:51:56.703Z',
                'rule': {
                    '===': [
                        '<<nodeResult>>',
                        {
                            'get': [
                                {...}, 'result'
                            ]
                        }
                    ]
                },
                'status': 0,
                'tenantId': '05f43f12-5865-46cd-8954-1af3dc575e88'
            }
        ]

        """

        request_url = self.config()["studioRulesUrl"]
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed get rules!",
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_rules_iterator(self) -> iter:
        """Get an iterator object that can be used to traverse rules.

        Returns:
            iter:
                A generator yielding one rule per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One rule at a time.

        """

        rules: list = self.get_rules()

        yield from rules

    # end method definition

    def get_rule(self, rule_id: str) -> dict | None:
        r"""Get a rule by its ID.

        Args:
            rule_id (str):
                The ID of the rule.

        Returns:
            dict | None:
                Rule data or none in case of an error.

        Example:
        {
            'id': '4d089d1e-205d-4ff4-8128-7c2a83bd2462',
            'name': 'evaluateLastToolResult',
            'description': 'Equivalent of previous "toolResult" check. Evaluates the result of last tool executed and compares it with a given string. Returns `true` or `false`. This is the equivalent of \n ```const lastTool = memory.response.called[memory.response.called.length - 1];\nreturn lastTool?.result === (andConditions[condition]);```',
            'createdAt': '2025-07-01T16:51:56.703Z',
            'updatedAt': '2025-07-01T16:51:56.703Z',
            'rule': {
                '===': [
                    '<<nodeResult>>',
                    {
                        'get': [
                            {...}, 'result'
                        ]
                    }
                ]
            },
            'status': 0,
            'tenantId': '05f43f12-5865-46cd-8954-1af3dc575e88'
        }

        """

        rule = self.get_model(model_type="rules", model_id=rule_id)

        return rule

    # end method definition

    def get_prompts(self) -> list | None:
        r"""Get all prompts.

        Returns:
            list:
                A list of all prompts.

        Example:
        [
            {
                'id': '1aeb9fa1-cb26-4b07-a736-20d25a4ab939',
                'name': 'general_system',
                'template': "Your name is Aviator and you are a friendly chatbot assisting users with their queries about documents. The DOCUMENTS contains text of tool calls, arguments and their responses in the following format:\n Tool '[test]' called with arguments '[args]' and returned: [tool response]. \n When responding: \n 1. If one or more tool responses are present, answer directly using the information in the tool response. Do not refer to the tool call or tool response explicitly. \n 2. If no tool response is present, reply that you do not know. \n 3. If the information is out of the scope of the document or you are unsure of the answer, reply that you do not know.  If the user explicitly requests to provide, show, display, generate a specific output format like a table, a list or a code block, please prioritize that format, when providing an answer. \nDOCUMENTS: {context}",
                'type': 0,
                'createdAt': '2025-07-01T16:51:56.703Z',
                'updatedAt': '2025-07-01T16:51:56.703Z',
                'version': None,
                'status': 0,
                'tenantId': '05f43f12-5865-46cd-8954-1af3dc575e88',
                'attributes': None,
                'description': None
            },
            ...
        ]

        """

        return self.get_models(model_type="prompts")

    # end method definition

    def get_prompts_iterator(self) -> iter:
        """Get an iterator object that can be used to traverse prompts.

        Returns:
            iter:
                A generator yielding one prompt per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One prompt at a time.

        """

        prompts: list = self.get_models(model_type="prompts")

        yield from prompts

    # end method definition

    def get_prompt(self, prompt_id: str) -> dict | None:
        r"""Get a prompt by its ID.

        Args:
            prompt_id (str):
                The ID of the prompt.

        Returns:
            dict | None:
                Prompt data or none in case of an error.

        Example:
        {
            'id': '1aeb9fa1-cb26-4b07-a736-20d25a4ab939',
            'name': 'general_system',
            'template': "Your name is Aviator and you are a friendly chatbot assisting users with their queries about documents. The DOCUMENTS contains text of tool calls, arguments and their responses in the following format:\n Tool '[test]' called with arguments '[args]' and returned: [tool response]. \n When responding: \n 1. If one or more tool responses are present, answer directly using the information in the tool response. Do not refer to the tool call or tool response explicitly. \n 2. If no tool response is present, reply that you do not know. \n 3. If the information is out of the scope of the document or you are unsure of the answer, reply that you do not know.  If the user explicitly requests to provide, show, display, generate a specific output format like a table, a list or a code block, please prioritize that format, when providing an answer. \nDOCUMENTS: {context}",
            'type': 0,
            'createdAt': '2025-07-01T16:51:56.703Z',
            'updatedAt': '2025-07-01T16:51:56.703Z',
            'version': None,
            'status': 0,
            'tenantId': '05f43f12-5865-46cd-8954-1af3dc575e88',
            'attributes': None,
            'description': None
        },

        """

        prompt = self.get_model(model_type="prompts", model_id=prompt_id)

        return prompt

    # end method definition

    def add_prompt(
        self,
        name: str,
        template: str,
        description: str,
        llm_model: str,
        attributes: dict | None = None,
    ) -> dict | None:
        """Add a prompt for a specific LLM.

        Args:
            name (str):
                A given name fpor the prompt.
            template (str):
                The actual prompt string.
            description (str):
                An arbitrary desciption of the prompt.
            llm_model (str):
                The name of the LLM that has been registered by calling add_llm().
            attributes (dict | None, optional):
                * "type": the type of the prompt, e.g. "system"

        Returns:
            dict | None:
                The data of the created prompt. This includes the prompt ID and the prompt version.

        Example:
        {
            'id': '9e491456-3b72-4fec-8e51-3af2b4f036fb',
            'name': 'cat_prompt',
            'template': 'Your name is Cat Aviator and you are an AI Assitant that answers questions and always ends answers with jokes about cats.',
            'description': 'This is a Cat prompt',
            'attributes': {'type': 'system'},
            'llmModel': 'qwen3:8b',
            'version': 1,
            'promptId': '3c96c5e3-dfa2-4aa8-9ce3-2080e0726241'
        }

        """

        request_url = self.config()["studioPromptsUrl"]
        request_header = self.request_header(service_type="studio")
        request_data = {
            "name": name,
            "template": template,
            "description": description,
            "llmModel": llm_model,
            "attributes": attributes,
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=request_data,
            timeout=None,
            show_error=True,
            failure_message="Failed to add prompt -> '%s' for LLM -> '{}'!".format(name),
        )

        return response

    # end method definition

    def update_prompt(self, name: str, instructions: list[str] | str) -> dict | None:
        """Update an existing prompt with additional instructions.

        Args:
            name (str):
                Name of the existing prompt.
            instructions (list[str] | str):
                If the instructions is a string, it will replace the existing prompt template.
                If the instructions is a list of strings, any missing instruction will be appended to the existing prompt template.

        """

        prompts = self.get_models(model_type="prompts", where={"name": name})

        if prompts:
            prompt = prompts[0]
            prompt_id = prompt.get("id")

        if prompt_id:
            prompt = self.get_prompt(prompt_id)

            if isinstance(instructions, list):
                # Add any missing instructions to the prompt template:
                missing_instructions = [instr for instr in instructions if instr not in prompt["template"]]
                if missing_instructions:
                    prompt["template"] += " ".join(missing_instructions)
            else:
                prompt["template"] = instructions

            self.logger.info("Updating prompt -> '%s'", name)
            self.logger.debug("Updating prompt data: %s", prompt)
            self.update_model(model_type="prompts", model_id=prompt_id, request_body=prompt)

        else:
            self.logger.error("Prompt -> '%s' not found, cannot update!", name)
            return None

    # end method definition

    def get_actions(self) -> list | None:
        """Get all actions.

        Returns:
            list:
                A list of all actions.

        Example:
        [
            {
                'id': '98dec337-8284-4d30-8a6d-0da099aa025a',
                'attributes': {'studio': 'routerAgent'},
                'klassId': '3d2d2500-483a-4af6-9103-79da80994852',
                'name': 'decision',
                'description': None,
                'discriminator': 1,
                'createdAt': '2025-07-02T06:45:04.117Z',
                'updatedAt': '2025-07-02T06:45:04.117Z',
                'version': 0,
                'status': 0,
                'graphId': '02a6ae86-dbf5-4007-ad66-090a145bc81a'
            },
            ...
        ]

        """

        return self.get_models(model_type="actions")

    # end method definition

    def get_actions_iterator(self) -> iter:
        """Get an iterator object that can be used to traverse actions.

        Returns:
            iter:
                A generator yielding one action per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One action at a time.

        """

        actions: list = self.get_models(model_type="actions")

        yield from actions

    # end method definition

    def get_action(self, action_id: str) -> dict | None:
        r"""Get a action by its ID.

        Args:
            action_id (str):
                The ID of the action.

        Returns:
            dict | None:
                Action data or none in case of an error.

        Example:
        {
            'id': '98dec337-8284-4d30-8a6d-0da099aa025a',
            'attributes': {'studio': 'routerAgent'},
            'klassId': '3d2d2500-483a-4af6-9103-79da80994852',
            'name': 'decision',
            'description': None,
            'discriminator': 1,
            'createdAt': '2025-07-02T06:45:04.117Z',
            'updatedAt': '2025-07-02T06:45:04.117Z',
            'version': 0,
            'status': 0,
            'graphId': '02a6ae86-dbf5-4007-ad66-090a145bc81a'
        },

        """

        action = self.get_model(model_type="actions", model_id=action_id)

        return action

    # end method definition

    def get_klasses(self) -> list | None:
        r"""Get all klasses.

        Returns:
            list:
                A list of all klasses.

        Example:
        [
            {
                'id': '20cfe232-cf03-4b77-a4e6-bc9339371a37',
                'name': 'RephraseSearch',
                'tenantId': 'eb6fee1e-da08-4046-9867-e96ac0ec5bdf',
                'path': '../langchain_tools/tools/rephraseSearch',
                'type': 8,
                'createdAt': '2025-07-02T06:45:04.099Z',
                'updatedAt': '2025-07-02T06:45:04.099Z',
                'description': None
            },
            ...
        ]

        """

        return self.get_models(model_type="klasses")

    # end method definition

    def get_klasses_iterator(self) -> iter:
        """Get an iterator object that can be used to traverse klasses.

        Returns:
            iter:
                A generator yielding one klass per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One klass at a time.

        """

        klasses: list = self.get_models(model_type="klasses")

        yield from klasses

    # end method definition

    def get_klass(self, klass_id: str) -> dict | None:
        r"""Get a klass by its ID.

        Args:
            klass_id (str):
                The ID of the klass.

        Returns:
            dict | None:
                Klass data or none in case of an error.

        Example:
        {
            'id': '20cfe232-cf03-4b77-a4e6-bc9339371a37',
            'name': 'RephraseSearch',
            'tenantId': 'eb6fee1e-da08-4046-9867-e96ac0ec5bdf',
            'path': '../langchain_tools/tools/rephraseSearch',
            'type': 8,
            'createdAt': '2025-07-02T06:45:04.099Z',
            'updatedAt': '2025-07-02T06:45:04.099Z',
            'description': None
        }

        """

        klass = self.get_model(model_type="klasses", model_id=klass_id)

        return klass

    # end method definition

    def get_graph_node_relationships(self, graph_id: str, node_id: str, relation_type: str) -> list | None:
        """Get all relations to prompts or rules for a graph node.

        Args:
            graph_id (str):
                The ID of the Graph to retrieve the relationships for.
            node_id (str):
                The ID of the Graph node to retrieve the relationships for.
            relation_type (str):
                This can either be "prompts" or "rules".

        Returns:
            list | None:
                A list of relationships for the node.

        Example:
        [
        ]

        """

        request_url = self.config()["studioGraphsUrl"] + "/" + graph_id + "/nodes/" + node_id + "/" + relation_type
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed get list of graph node relationships!",
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_graph_node_relationships_iterator(
        self, graph_id: str, node_id: str, relation_type: str | list = "prompts"
    ) -> iter:
        """Get an iterator object that can be used to traverse prompts.

        Args:
            graph_id (str):
                The ID of the Graph to retrieve the relationships for.
            node_id (str):
                The ID of the Graph node to retrieve the relationships for.
            relation_type (str):
                This can either be "prompts" or "rules".

        Returns:
            iter:
                A generator yielding one relationship per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One relationship at a time.

        """

        relationships: list = self.get_graph_node_relationships(
            graph_id=graph_id, node_id=node_id, relation_type=relation_type
        )
        if not relationships:
            return

        yield from relationships

    # end method definition

    def is_ready(self, service: str, wait: bool = False) -> bool | None:
        """Check if service is ready to be used.

        Args:
            service (str):
                The name of the service to check.
            wait (bool, optional):
                If True, will wait until the service is ready.
                Default is False.

        Returns:
            bool | None:
                True if ready, False if not, None if unknown service.

        """

        match service.lower():
            case "studio":
                request_url = self.config()["studioUrl"]

            case "chat":
                request_url = self.config()["chatUrl"]

            case _:
                self.logger.error("Service -> '%s' is not supported for readiness check!", service)
                return None

        if wait:
            self.logger.info("Waiting for Aviator %s to be available at %s ...", service, request_url)

        response = None
        while not response:
            response = self.do_request(
                url=request_url,
                method="GET",
                max_retries=-1,
                timeout=None,
                show_error=False,
                failure_message=f"Aviator {service} is not available!",
                parse_request_response=False,
            )

            if not wait:
                break

        # Return True if we got a response, False if not:
        return response is not None

    # end method definition

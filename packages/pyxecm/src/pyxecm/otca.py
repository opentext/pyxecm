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

REQUEST_TIMEOUT = 60
REQUEST_RETRY_DELAY = 20
REQUEST_MAX_RETRIES = 2

default_logger = logging.getLogger(MODULE_NAME)

try:
    from pyvis.network import Network

    pyvis_installed = True
except ModuleNotFoundError:
    default_logger.warning(
        "Module pyvis is not installed. Customizer will not support graph visualization.",
    )
    pyvis_installed = False


class OTCA:
    """Interact with Content Aviator REST API."""

    logger: logging.Logger = default_logger

    _config: dict
    _context = ""
    _embed_token: str | None = None
    _chat_token: str | None = None
    _chat_token_hashed: str | None = None
    _node_dictionary: dict = {}

    def __init__(
        self,
        chat_url: str,
        embed_url: str,
        studio_url: str,
        otds_url: str,
        client_id: str,
        client_secret: str,
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
            content_system (dict | None):
                The Content System configuration for the services which control the authentication.
            otcs_object (OTCS):
                The OTCS object..
            synonyms (list):
                List of synonyms that are used to generate a better response to the user.
            inline_citation (bool):
                Enable/Disable citations in the answers.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otca")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        otca_config = {}

        otca_config["chatUrl"] = chat_url + "/v1/chat"
        otca_config["searchUrl"] = chat_url + "/v1/context"
        otca_config["embedUrl"] = embed_url + "/v1/embeddings"
        otca_config["studioGraphsUrl"] = studio_url + "/studio/v1/graphs"
        otca_config["studioAgentsUrl"] = studio_url + "/studio/v1/agents"
        otca_config["studioToolsUrl"] = studio_url + "/studio/v1/tools"
        otca_config["studioRulesUrl"] = studio_url + "/studio/v1/rules"
        otca_config["studioModelsUrl"] = studio_url + "/studio/v1/api/models"

        otca_config["content_system"] = content_system if content_system else {"chat": "xecm", "embed": "xecm"}
        otca_config["clientId"] = client_id
        otca_config["clientSecret"] = client_secret
        otca_config["otdsUrl"] = otds_url

        otca_config["synonyms"] = synonyms if synonyms else []
        otca_config["inlineCitation"] = inline_citation

        self._config = otca_config
        self.otcs_object = otcs_object

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
        content_system = self.config()["content_system"].get(service_type, "none")

        if content_system == "none":
            return request_header

        if service_type == "chat":
            if self._chat_token is None:
                self.authenticate_chat()

            if content_system == "xecm":
                request_header["Authorization"] = "Bearer {}".format(self._chat_token_hashed)
            elif content_system == "xecm-direct":
                request_header["otcsticket"] = self._chat_token

        elif service_type == "embed":
            if self._embed_token is None:
                self.authenticate_embed()
            request_header["Authorization"] = "Bearer {}".format(self._embed_token)

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
        timeout: int | None = REQUEST_TIMEOUT,
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
            timeout (int | None, optional):
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

    def chat(self, context: str | None, messages: list, where: list) -> dict:
        r"""Process a chat interaction with Content Aviator.

        Chat requests are meant to be called as end-users.  This should involve
        passing the end-user's access token via the Authorization HTTP header.
        The chat service use OTDS's token endpoint to ensure that the token is valid.

        Args:
            context (str | None):
                Context for the current conversation
                (empty initially, returned by previous responses from POST /v1/chat).
            messages (list):
                List of messages from conversation history.
            where (list):
                Metadata name/value pairs for the query.
                Could be used to specify workspaces, documents, or other criteria in the future.
                Values need to match those passed as metadata to the embeddings API.

        Returns:
            dict: Conversation status

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
        request_header = self.request_header()

        chat_data = {
            "context": context,
            "messages": messages,
            "where": where,
            # "synonyms": self.config()["synonyms"],
            # "inlineCitation": self.config()["inlineCitation"],
        }

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=chat_data,
            timeout=None,
            failure_message="Failed to chat with Content Aviator",
        )

    # end method definition

    def search(
        self, query: str, document_ids: list, workspace_ids: list, threshold: float = 0.5, num_results: int = 10
    ) -> dict:
        """Semantic search for text chunks.

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
        if not workspace_ids and not document_ids:
            self.logger.error("Either workspace ID(s) or document ID(s) need to be provided!")
            return None

        request_url = self.config()["searchUrl"]
        request_header = self.request_header()

        search_data = {
            "query": query,
            "threshold": threshold,
            "numResults": num_results,
            "metadata": [],
        }

        for document_id in document_ids:
            search_data["metadata"].append({"documentID": str(document_id)})
        for workspace_id in workspace_ids:
            search_data["metadata"].append({"workspaceID": str(workspace_id)})

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=search_data,
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
    ) -> dict:
        """Embed a given content.

        Requests are meant to be called as a service user. This would involve passing a service user's access token
        (token from a particular OAuth confidential client, using client credentials grant).

        Args:
            content (str | None):
                Content to be embedded. This is a document chunk. Can be empty for "delete" operations.
            operation (str):
                This can be either "add", "update" or "delete".
            document_id (int):
                The ID of the document the content originates from. This becmes metadata in the vector store.
            workspace_id (int):
                The ID of the workspace the content originates from. This becomes metadata in the vector store.
            additional_metadata (dict | None):
                Dictionary with additional metadata.

        Returns:
            dict:
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

    def get_graphs(self) -> list | None:
        """Get all graphs.

        Returns:
            list:
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

    def get_graph(self, graph_id: str) -> dict | None:
        """Get a graph by its ID.

        Args:
            graph_id (str):
                The ID of the graph.

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

        request_url = self.config()["studioGraphsUrl"] + "/" + graph_id
        request_header = self.request_header(service_type="studio")

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed get graphs",
        )

    # end method definition

    def get_graph_nodes(self, graph_id: str) -> list | None:
        """Get all nodes of a graph.

        Args:
            graph_id (str):
                The ID of the Graph to retrieve the nodes for.

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

        request_url = self.config()["studioGraphsUrl"] + "/" + graph_id + "/nodes"
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed get list of graph nodes!",
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_graph_nodes_iterator(self, graph_id: str) -> iter:
        """Get an iterator object that can be used to traverse graph nodes.

        Returns:
            iter:
                A generator yielding one node per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One node at a time.

        """

        nodes: list = self.get_graph_nodes(graph_id=graph_id)

        yield from nodes

    # end method definition

    def get_graph_nodes_by_name(self, name: str) -> list | None:
        """Get all nodes of a graph by name.

        Args:
            name (str):
                The Name of the Graph to retrieve the nodes for.

        Returns:
            list | None:
                A list of all nodes of the graph.

        """

        graphs = self.get_graphs()

        if graphs is None:
            return None

        graph = next((g for g in graphs if g["name"] == name), None)

        if graph is None:
            self.logger.error("Graph -> '%s' not found!", name)
            return None

        request_url = self.config()["studioGraphsUrl"] + "/" + graph["id"] + "/nodes"
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed get list of graphs!",
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_graph_edges(self, graph_id: str) -> list | None:
        """Get all edges of a graph.

        Args:
            graph_id (str):
                The ID of the Graph to retrieve the edges for.

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

        request_url = self.config()["studioGraphsUrl"] + "/" + graph_id + "/edges"
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed get list of graph edges!",
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_graph_edges_iterator(self, graph_id: str) -> iter:
        """Get an iterator object that can be used to traverse graph edges.

        Returns:
            iter:
                A generator yielding one edge per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One edge at a time.

        """

        edges: list = self.get_graph_edges(graph_id=graph_id)

        yield from edges

    # end method definition

    def visualize_graph(self, graph_id: str) -> str:
        """Visualize a graph.

        Args:
            graph_id (str):
                The ID of the graph.

        Returns:
            str: Filename of the generated html file

        """

        if not pyvis_installed:
            self.logger.warning("Cannot visualize graph. Python module pyvis not installed!")
            return None

        graph = self.get_graph(graph_id=graph_id)
        graph_id = graph["id"]
        graph_name = graph["name"]
        net = Network(notebook=False, directed=True, height="1000px", width="100%", filter_menu=True, select_menu=True)
        net.heading = f"Aviator Studio graph: {graph_name}"
        nodes = self.get_graph_nodes_iterator(graph_id=graph_id)
        for node in nodes:
            node_id = node["id"]
            node_name = node["name"]
            node_attributes = node["attributes"]
            self._node_dictionary[(graph_id, node_id)] = node_name
            if node_attributes and "APISchema" in node_attributes:
                net.add_node(n_id=node_id, label=node_name, title=json.dumps(node, indent=2), color="green")
            else:
                net.add_node(n_id=node_id, label=node_name, title=json.dumps(node, indent=2))
            relationships = self.get_graph_node_relationships_iterator(
                graph_id=graph_id, node_id=node_id, relation_type="rules"
            )
            for relationship in relationships:
                for rule in relationship["rules"] or []:
                    net.add_node(
                        n_id=rule["id"], label=rule["name"], title=json.dumps(rule, indent=2), shape="box", color="red"
                    )
                    net.add_edge(source=node_id, to=rule["id"])
            relationships = self.get_graph_node_relationships_iterator(
                graph_id=graph_id, node_id=node_id, relation_type="prompts"
            )
            for relationship in relationships:
                for prompt in relationship["prompts"] or []:
                    net.add_node(
                        n_id=prompt["id"],
                        label=prompt["name"],
                        title=json.dumps(prompt, indent=2),
                        shape="oval",
                        color="green",
                    )
                    net.add_edge(source=node_id, to=prompt["id"])
        edges = self.get_graph_edges_iterator(graph_id=graph_id)
        for edge in edges:
            edge_source_id = edge["sourceId"]
            edge_target_id = edge["targetId"]
            net.add_edge(source=edge_source_id, to=edge_target_id)

        html_file = "{}.html".format(graph_name)
        net.save_graph(html_file)
        self.logger.info("Graph visualization saved to -> %s", html_file)

        return html_file

    # end method definition

    def get_model_types(self) -> list:
        """Get a list of all model types. Hardcoded.

        Returns:
            list:
                Model types.

        """

        return ["tenants", "graphs", "nodes", "edges", "actions", "tools", "prompts", "rules", "klasses"]

    # end method definition

    def get_models(self, model_type: str) -> list | None:
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

        Returns:
            list | None:
                A list of all models of a given type.

        """

        request_url = self.config()["studioModelsUrl"] + "/" + model_type
        request_header = self.request_header(service_type="studio")

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            show_error=True,
            failure_message="Failed to get list of models!",
        )

        if response is None:
            return None

        return response.get("results", [])

    # end method definition

    def get_models_iterator(self, model_type: str) -> iter:
        """Get an iterator object that can be used to traverse models.

        Returns:
            iter:
                A generator yielding one model per iteration.
                If the REST API fails, returns no value.

        Yields:
            Iterator[iter]:
                One edge at a time.

        """

        models: list = self.get_models(model_type=model_type)

        yield from models

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

        models = self.get_models(model_type=model_type)
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

        self.logger.info("Updating existing model -> '%s' (%s)", model_type, model_id)

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
                        "responseTemplate": {},
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
                self.logger.error("%s is missing in provided request body for tool registration!", key)
                return None

        # Check if the tool already exists and need to be updated only:
        self.logger.debug("Check if tool -> '%s' already exists...", request_body["name"])
        model = self.get_model_by_type_and_name(model_type="tools", name=request_body["name"])
        if model:
            self.logger.info("Updating existing tool -> '%s'...", request_body["name"])

            update_body = {
                "description": request_body["description"],
                "attributes": {**model.get("attributes", {}), "APISchema": request_body["APISchema"]},
            }
            response = self.update_model(model_type="tools", model_id=model["id"], request_body=update_body)
            if not response:
                self.logger.error("Failed to update model -> '%s' (%s)", request_body["name"], model["id"])
        else:
            self.logger.info("Registering new tool -> '%s'...", request_body["name"])
            request_header = self.request_header(service_type="studio")
            request_url = self.config()["studioToolsUrl"]
            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                json_data=request_body,
                timeout=None,
                show_error=True,
                failure_message="Failed to register tool -> '{}'!".format(request_body["name"]),
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
                One tool at a time.

        """

        prompts: list = self.get_models(model_type="prompts")

        yield from prompts

    # end method definition

    def get_prompt(self, prompt_id: str) -> dict | None:
        r"""Get a rule by its ID.

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

    def get_actions(self) -> list | None:
        r"""Get all actions.

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

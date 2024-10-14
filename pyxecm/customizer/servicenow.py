"""
ServiceNow Module to interact with the ServiceNow API
See: 

Class: ServiceNow
Methods:

__init__ : class initializer
thread_wrapper: Function to wrap around threads to catch exceptions during exection
config : Returns the configuration dictionary
get_data: Get the Data object that holds all processed Knowledge base Articles (Pandas Data Frame)
request_header: Returns the request header for ServiceNow API calls
parse_request_response: Parse the REST API responses and convert
                        them to Python dict in a safe way
exist_result_item: Check if an dict item is in the response
                   of the ServiceNow API call
get_result_value: Check if a defined value (based on a key) is in the ServiceNow API response

authenticate : Authenticates at ServiceNow API
get_oauth_token: Returns the OAuth access token.

get_object: Get an ServiceNow object based on table name and ID
get_summary: Get summary object for an article.
get_table: Retrieve a specified ServiceNow table data (row or values)
get_table_count: Get number of table rows (e.g. Knowledge Base Articles) matching the query
                 (or if query = "" it should be the total number)
get_knowledge_bases: Get the configured knowledge bases in ServiceNow
get_knowledge_base_articles: Get selected / filtered Knowledge Base articles
make_file_names_unique: Make file names unique if required. The mutable
                        list is changed "in-place".
download_attachments: Download the attachments of a Knowledge Base Article (KBA) in ServiceNow.
load_articles: Main method to load ServiceNow articles in a Data Frame and
               download the attchments.
load_articles_worker: Worker Method for multi-threading.
load_article: Process a single KBA: download attachments (if any)
              and add the KBA to the Data Frame.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import os
import json
import logging
import urllib.parse
import threading
import traceback
from functools import cache
import time

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError, RequestException
from pyxecm.helper.data import Data

logger = logging.getLogger("pyxecm.customizer.servicenow")

REQUEST_HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

REQUEST_TIMEOUT = 60

KNOWLEDGE_BASE_PATH = "/tmp/attachments"

# ServiceNow database tables. Table names starting with "u_" are custom OpenText tables:
SN_TABLE_CATEGORIES = "kb_category"
SN_TABLE_KNOWLEDGE_BASES = "kb_knowledge_base"
SN_TABLE_KNOWLEDGE_BASE_ARTICLES = "u_kb_template_technical_article_public"
SN_TABLE_KNOWLEDGE_BASE_ARTICLES_PRODUCT = (
    "u_kb_template_product_documentation_standard"
)
SN_TABLE_RELATED_PRODUCTS = "cmdb_model"
SN_TABLE_PRODUCT_LINES = "u_ot_product_model"
SN_TABLE_PRODUCT_VERSIONS = "u_ot_product_model_version"
SN_TABLE_ATTACHMENTS = "sys_attachment"


class ServiceNow(object):
    """Used to retrieve and automate stettings in ServiceNow."""

    _config: dict
    _access_token = None
    _session = None
    _data: Data = None
    _thread_number = 3
    _download_dir = ""

    def __init__(
        self,
        base_url: str,
        auth_type: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        token_url: str = "",
        thread_number: int = 3,
        download_dir: str = KNOWLEDGE_BASE_PATH,
    ):
        """Initialize the Service Now object

        Args:
            base_url (str): base URL of the ServiceNow tenant
            auth_type (str): authorization type, either "oauth" or "basic"
            client_id (str): ServiceNow Client ID
            client_secret (str): ServiceNow Client Secret
            username (str): user name in Saleforce
            password (str): password of the user
            token_url (str, optional): Token URL for ServiceNow login via OAuth.
            thread_number (int, optional): number of threads for parallel processing. Default is 3.
            download_path (str): path to stored downloaded files from ServiceNow
        """

        servicenow_config = {}

        # Store the credentials and parameters in a config dictionary:
        servicenow_config["baseUrl"] = base_url
        servicenow_config["authType"] = auth_type
        servicenow_config["clientId"] = client_id
        servicenow_config["clientSecret"] = client_secret
        servicenow_config["username"] = username
        servicenow_config["password"] = password
        if not token_url:
            token_url = base_url + "/oauth_token.do"
        else:
            servicenow_config["tokenUrl"] = token_url

        servicenow_config["restUrl"] = servicenow_config["baseUrl"] + "/api/now/"
        servicenow_config["tableUrl"] = servicenow_config["restUrl"] + "table"
        servicenow_config["knowledgeUrl"] = (
            servicenow_config["restUrl"] + "table/kb_knowledge"
        )
        servicenow_config["knowledgeBaseUrl"] = (
            servicenow_config["restUrl"] + "table/" + SN_TABLE_KNOWLEDGE_BASES
        )
        servicenow_config["attachmentsUrl"] = (
            servicenow_config["restUrl"] + "table/" + SN_TABLE_ATTACHMENTS
        )
        servicenow_config["attachmentDownloadUrl"] = (
            servicenow_config["restUrl"] + "attachment"
        )
        servicenow_config["statsUrl"] = servicenow_config["restUrl"] + "stats"

        self._config = servicenow_config

        self._session = requests.Session()

        self._data = Data()

        self._thread_number = thread_number

        self._download_dir = download_dir

    # end method definition

    def thread_wrapper(self, target, *args, **kwargs):
        """Function to wrap around threads to catch exceptions during exection"""

        try:
            target(*args, **kwargs)
        except Exception as e:
            thread_name = threading.current_thread().name
            logger.error(
                "Thread '%s': failed with exception -> %s", thread_name, str(e)
            )
            logger.error(traceback.format_exc())

    # end method definition

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    # end method definition

    def get_data(self) -> Data:
        """Get the Data object that holds all processed Knowledge base Articles

        Returns:
            Data: Datastructure with all processed articles.
        """

        return self._data

    # end method definition

    def request_header(self, content_type: str = "") -> dict:
        """Returns the request header used for Application calls.
           Consists of Bearer access token and Content Type

        Args:
            content_type (str, optional): custom content type for the request.
                                          Typical values:
                                          * application/json - Used for sending JSON-encoded data
                                          * application/x-www-form-urlencoded - The default for HTML forms. Data is sent as key-value pairs in the body of the request, similar to query parameters
                                          * multipart/form-data - Used for file uploads or when a form includes non-ASCII characters
        Return:
            dict: request header values
        """

        request_header = {}

        request_header = REQUEST_HEADERS

        if self.config()["authType"] == "oauth":
            request_header["Authorization"] = ("Bearer {}".format(self._access_token),)

        if content_type:
            request_header["Content-Type"] = content_type

        return request_header

    # end method definition

    def parse_request_response(
        self,
        response_object: requests.Response,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Converts the request response (JSon) to a Python dict in a safe way
           that also handles exceptions. It first tries to load the response.text
           via json.loads() that produces a dict output. Only if response.text is
           not set or is empty it just converts the response_object to a dict using
           the vars() built-in method.

        Args:
            response_object (object): this is reponse object delivered by the request call
            additional_error_message (str, optional): use a more specific error message
                                                      in case of an error
            show_error (bool): True: write an error to the log file
                               False: write a warning to the log file
        Returns:
            dict: response information or None in case of an error
        """

        if not response_object:
            return None

        try:
            if response_object.text:
                dict_object = json.loads(response_object.text)
            else:
                dict_object = vars(response_object)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSON. {}; error -> {}".format(
                    additional_error_message, exception
                )
            else:
                message = "Cannot decode response as JSON; error -> {}".format(
                    exception
                )
            if show_error:
                logger.error(message)
            else:
                logger.warning(message)
            return None
        else:
            return dict_object

    # end method definition

    def exist_result_item(self, response: dict, key: str, value: str) -> bool:
        """Check existence of key / value pair in the response properties of an ServiceNow API call.

        Args:
            response (dict): REST response from an Salesforce API call
            key (str): property name (key)
            value (str): value to find in the item with the matching key
        Returns:
            bool: True if the value was found, False otherwise
        """

        if not response:
            return False

        if "result" in response:
            records = response["result"]
            if not records or not isinstance(records, list):
                return False

            for record in records:
                if value == record[key]:
                    return True
        else:
            if not key in response:
                return False
            if value == response[key]:
                return True

        return False

    # end method definition

    def get_result_value(
        self,
        response: dict,
        key: str,
        index: int = 0,
    ) -> str | None:
        """Get value of a result property with a given key of an ServiceNow API call.

        Args:
            response (dict): REST response from an Salesforce REST Call
            key (str): property name (key)
            index (int, optional): Index to use (1st element has index 0).
                                   Defaults to 0.
        Returns:
            str: value for the key, None otherwise
        """

        # ServiceNow responses should always have a "result":
        if not response or not "result" in response:
            return None

        values = response["result"]
        if not values:
            return None

        # Service now can either have a dict or a list structure
        # in "results":
        if isinstance(values, list) and len(values) - 1 < index:
            value = values[index][key]
        elif isinstance(values, dict) and key in values:
            value = values[key]
        else:
            logger.error("Illegal data type in ServiceNow response!")
            return None

        return value

    # end method definition

    def authenticate(self, auth_type: str) -> str | None:
        """Authenticate at ServiceNow with client ID and client secret or with basic authentication.

        Args:
            auth_type (str): this can be "basic" or "oauth"
        Returns:
            str: session token or None in case of an error

        """

        self._session.headers.update(self.request_header())

        if auth_type == "basic":
            username = self.config()["username"]
            password = self.config()["password"]
            if not self._session:
                self._session = requests.Session()
            self._session.auth = HTTPBasicAuth(username, password)
            return self._session.auth
        elif auth_type == "oauth":
            token = self.get_oauth_token()
            self._session.headers.update({"Authorization": "Bearer {}".format(token)})

            return token
        else:
            logger.error("Unsupported authentication type")
            return None

    # end method definition

    def get_oauth_token(self) -> str:
        """Returns the OAuth access token.

        Returns:
            str: Access token
        """

        token_post_body = {
            "grant_type": "client_credentials",
            "client_id": self.config()["client_id"],
            "client_secret": self.config()["client_secret"],
        }

        response = requests.post(
            url=self.config()["token_url"],
            data=token_post_body,
            timeout=REQUEST_TIMEOUT,
        )

        if response.ok:
            authenticate_dict = self.parse_request_response(response)
            if not authenticate_dict:
                return None
            else:
                # Store authentication access_token:
                self._access_token = authenticate_dict["access_token"]
                logger.debug("Access Token -> %s", self._access_token)
        else:
            logger.error(
                "Failed to request an Service Now Access Token; error -> %s",
                response.text,
            )
            return None

        return self._access_token

    # end method definition

    @cache
    def get_object(self, table_name: str, sys_id: str) -> dict | None:
        """Get an ServiceNow object based on table name and ID

        Args:
            table_name (str): Name of the ServiceNow table.
            sys_id (str): ID of the data set to resolve.

        Returns:
            dict | None: dictionary of fields of resulting table row or None
                         in case an error occured.
        """

        if not table_name:
            logger.error("Table name is missing!")
            return None

        if not sys_id:
            logger.error("System ID of item to lookup is missing!")
            return None

        request_header = self.request_header()

        request_url = self.config()["restUrl"] + "table/{}/{}".format(
            table_name, sys_id
        )

        try:
            response = self._session.get(url=request_url, headers=request_header)
            data = self.parse_request_response(response)

            return data
        except HTTPError as http_err:
            logger.error(
                "HTTP error occurred while resolving -> %s in table -> '%s': %s",
                sys_id,
                table_name,
                str(http_err),
            )
        except RequestException as req_err:
            logger.error(
                "Request error occurred while resolving -> %s in table -> '%s': %s",
                sys_id,
                table_name,
                str(req_err),
            )
        except Exception as err:
            logger.error(
                "An error occurred while resolving -> %s in table -> '%s': %s",
                sys_id,
                table_name,
                str(err),
            )

        return None

    # end method definition

    def get_summary(self, summary_sys_id: str) -> dict | None:
        """Get summary object for an article.

        Args:
            summary_sys_id (str): System ID of the article

        Returns:
            dict | None: dictionary with the summary
        """

        return self.get_object(table_name="kb_knowledge_summary", sys_id=summary_sys_id)

    # end method definition

    def get_table(
        self,
        table_name: str,
        query: str = "",
        fields: list | None = None,
        limit: int | None = 10,
        offset: int = 0,
        error_string: str = "",
    ) -> list | None:
        """Retrieve a specified ServiceNow table data (row or values).

        Args:
            table_name (str): Name of the ServiceNow table
            query (str, optional): Query to filter the table rows (e.g. articles).
            fields (list, optional): Just return the fileds in this list.
                                     Defaults to None which means to deliver
                                     all fields.
            limit (int, optional): Number of results to return. None = unlimited.
            offset (int, optional): first item to return (for chunking)
            error_string (str, optional): custom error string

        Returns:
            list | None: List or articles or None if the request fails.
        """

        request_header = self.request_header()

        params = {}

        if query:
            params["sysparm_query"] = query
        if fields:
            params["sysparm_fields"] = ",".join(fields)
        if limit:
            params["sysparm_limit"] = limit
        if offset:
            params["sysparm_offset"] = offset

        encoded_query = urllib.parse.urlencode(params, doseq=True)

        request_url = self.config()["tableUrl"] + "/{}?{}".format(
            table_name, encoded_query
        )

        try:
            while True:
                response = self._session.get(
                    url=request_url, headers=request_header  # , params=params
                )
                data = self.parse_request_response(response)

                if response.status_code == 200:
                    return data.get("result", [])
                elif response.status_code == 202:
                    logger.warning(
                        "Service Now returned <202 Accepted> -> throtteling, retrying ..."
                    )
                    time.sleep(1000)
                else:
                    return None

        except HTTPError as http_err:
            logger.error("%sHTTP error -> %s!", error_string, str(http_err))
        except RequestException as req_err:
            logger.error("%sRequest error -> %s!", error_string, str(req_err))
        except Exception as err:
            logger.error("%sError -> %s!", error_string, str(err))

        return None

    # end method definition

    def get_table_count(
        self,
        table_name: str,
        query: str | None = None,
    ) -> int:
        """Get number of table rows (e.g. Knowledge Base Articles) matching the query
           (or if query = "" it should be the total number)

        Args:
            table_name (str): name of the ServiceNow table
            query (str, optional): Query string to filter the results. Defaults to "".

        Returns:
            int: Number of table rows.
        """

        request_header = self.request_header()

        params = {"sysparm_count": "true"}

        if query:
            params["sysparm_query"] = query

        encoded_query = urllib.parse.urlencode(params, doseq=True)

        request_url = self.config()["statsUrl"] + "/{}?{}".format(
            table_name, encoded_query
        )

        try:
            response = self._session.get(
                url=request_url, headers=request_header, timeout=600
            )
            data = self.parse_request_response(response)
            return int(data["result"]["stats"]["count"])
        except HTTPError as http_err:
            logger.error("HTTP error occurred -> %s!", str(http_err))
        except RequestException as req_err:
            logger.error("Request error occurred -> %s!", str(req_err))
        except Exception as err:
            logger.error("An error occurred -> %s!", str(err))

        return None

    # end method definition

    def get_categories(self) -> list | None:
        """Get the configured knowledge base categories in ServiceNow.

        Returns:
            list | None: list of configured knowledge base categories or None in case of an error.

            Example:
            [
                {
                    'sys_mod_count': '2',
                    'active': 'true',
                    'full_category': 'Patch / Rollup/Set',
                    'label': 'Rollup/Set',
                    'sys_updated_on': '2022-04-04 16:33:57',
                    'sys_domain_path': '/',
                    'sys_tags': '',
                    'parent_table': 'kb_category',
                    'sys_id': '05915bc91b1ac9109b6987b7624bcbed',
                    'sys_updated_by': 'vbalachandra@opentext.com',
                    'parent_id': {
                        'link': 'https://support-qa.opentext.com/api/now/table/kb_category/395093891b1ac9109b6987b7624bcb1b',
                        'value': '395093891b1ac9109b6987b7624bcb1b'
                    },
                    'sys_created_on': '2022-03-16 09:53:56',
                    'sys_domain': {
                        'link': 'https://support-qa.opentext.com/api/now/table/sys_user_group/global',
                        'value': 'global'
                    },
                    'value': 'rollup_set',
                    'sys_created_by': 'tiychowdhury@opentext.com'
                }
            ]
        """

        return self.get_table(
            table_name=SN_TABLE_CATEGORIES,
            error_string="Cannot get Categories; ",
            limit=50,
        )

    # end method definition

    def get_knowledge_bases(self) -> list | None:
        """Get the configured knowledge bases in ServiceNow.

        Returns:
            list | None: list of configured knowledge bases or None in case of an error.

            Example:
            [
                {
                    'mandatory_fields': '',
                    'template': '',
                    'enable_socialqa': 'false',
                    'icon': '', 'description': '',
                    'question_annotation': '',
                    'sys_updated_on': '2022-10-05 18:55:55',
                    'title': 'Support articles, alerts & useful tools',
                    'disable_suggesting': 'false',
                    'related_products': '',
                    'sys_id': '58819851db61b41068cfd6c4e29619bf',
                    'disable_category_editing': 'true',
                    'enable_blocks': 'true',
                    'sys_updated_by': 'nmohamme@opentext.com',
                    'article_validity': '',
                    'disable_commenting': 'true',
                    'sys_created_on': '2021-07-23 11:37:50',
                    'sys_domain': {...},
                    'kb_version': '3',
                    'sys_created_by': 'marquezj',
                    'table': 'kb_knowledge',
                    'order': '',
                    'owner': {
                        'link': 'https://support.opentext.com/api/now/table/sys_user/053429e31b5f0114fea2ec20604bcb95',
                        'value': '053429e31b5f0114fea2ec20604bcb95'
                    },
                    'retire_workflow': {
                        'link': 'https://support.opentext.com/api/now/table/wf_workflow/6b3e7ce6dbedb81068cfd6c4e2961936',
                        'value': '6b3e7ce6dbedb81068cfd6c4e2961936'
                    },
                    'languages': 'en,fq,de,ja,es,pb',
                    'workflow': {
                        'link': 'https://support.opentext.com/api/now/table/wf_workflow/184cb8e2dbedb81068cfd6c4e296199c',
                        'value': '184cb8e2dbedb81068cfd6c4e296199c'
                    },
                    'approval_description': '',
                    'disable_mark_as_helpful': 'false',
                    'sys_mod_count': '76',
                    'active': 'true',
                    'sys_domain_path': '/',
                    'sys_tags': '',
                    'application': {
                        'link': 'https://support.opentext.com/api/now/table/sys_scope/global',
                        'value': 'global'
                    },
                    'card_color': '',
                    'disable_rating': 'false',
                    'create_translation_task': 'false',
                    'kb_managers': 'acab67001b6b811461a7a8e22a4bcbbe,7ab0b6801ba205d061a7a8e22a4bcbec,2a685f4c1be7811461a7a8e22a4bcbfd,6cc3c3d2db21781068cfd6c4e2961962,053429e31b5f0114fea2ec20604bcb95,5454eb441b6b0514fea2ec20604bcbfc,3a17970c1be7811461a7a8e22a4bcb23'
                },
                ...
            ]
        """

        return self.get_table(
            table_name=SN_TABLE_KNOWLEDGE_BASES,
            error_string="Cannot get Knowledge Bases; ",
        )

    # end method definition

    def get_knowledge_base_articles(
        self,
        table_name: str = SN_TABLE_KNOWLEDGE_BASE_ARTICLES,
        query: str = "",
        fields: list | None = None,
        limit: int | None = 10,
        offset: int = 0,
    ) -> list | None:
        """Get selected / filtered Knowledge Base articles

        Args:
            query (str, optional): Query to filter the the articles.
            fields (list, optional): Just return the fileds in this list.
                                     Defaults to None which means to deliver
                                     all fields.
            limit (int, optional): Number of results to return. None = unlimited.
            offset (int, optional): first item to return (for chunking)

        Returns:
            list | None: List or articles or None if the request fails.

            Example:
            [
                {
                    'parent': '',
                    'wiki': None,
                    'rating': '',
                    'language': 'en',
                    'source': '',
                    'sys_updated_on': '2024-02-28 21:37:47',
                    'number': 'KB0530086',
                    'u_sub_product_line': 'cc1c280387655d506d9a2f8f8bbb35e0',
                    'sys_updated_by': 'scotts@opentext.com',
                    'sys_created_on': '2024-02-28 21:37:16',
                    'sys_domain': {
                        'link': 'https://support.opentext.com/api/now/table/sys_user_group/global',
                        'value': 'global'
                    },
                    'workflow_state': 'published',
                    'text': '',
                    'sys_created_by': 'scotts@opentext.com',
                    'scheduled_publish_date': '',
                    'image': '',
                    'author': {
                        'link': 'https://support.opentext.com/api/now/table/sys_user/ffd35065875499109fdd2f8f8bbb353f',
                        'value': 'ffd35065875499109fdd2f8f8bbb353f'
                    },
                    'u_related_products_text_search': '<br /><li>LearnFlex APP0578<br /></li>',
                    'can_read_user_criteria': 'de3a815b1b0601109b6987b7624bcba6',
                    'active': 'true',
                    'cannot_read_user_criteria': '',
                    'published': '2024-02-28',
                    'helpful_count': '0',
                    'sys_domain_path': '/',
                    'version': {
                        'link': 'https://support.opentext.com/api/now/table/kb_version/7cd172cf1b6cca10d7604223cd4bcb99',
                        'value': '7cd172cf1b6cca10d7604223cd4bcb99'
                    },
                    'meta_description': 'In LearnFlex, what types of messages are in message management?',
                    'kb_knowledge_base': {
                        'link': 'https://support.opentext.com/api/now/table/kb_knowledge_base/58819851db61b41068cfd6c4e29619bf',
                        'value': '58819851db61b41068cfd6c4e29619bf'
                    },
                    'meta': 'LearnFlex, 384, Message_Management, Message',
                    'u_platform_choice': '',
                    'topic': 'General',
                    'display_number': 'KB0530086 v3.0',
                    'u_product_line': '1f401ecc1bf6891061a7a8e22a4bcb7d',
                    'base_version': {
                        'link': 'https://support.opentext.com/api/now/table/kb_knowledge/740fbd4547651910ab0a9ed7536d4350',
                        'value': '740fbd4547651910ab0a9ed7536d4350'
                    },
                    'short_description': 'LearnFlex - What Types of Messages are in Message Management?',
                    'u_available_translations': 'English',
                    'u_limited_release': 'No',
                    'u_internal_review': '',
                    'roles': '',
                    'direct': 'false',
                    'description': '',
                    'disable_suggesting': 'false',
                    'related_products': '52609e001b3a891061a7a8e22a4bcb96',
                    'sys_class_name': 'u_kb_template_technical_article_public',
                    'article_id': '740fbd4547651910ab0a9ed7536d4350',
                    'sys_id': '91b13e8f1b6cca10d7604223cd4bcbc1',
                    'use_count': '0',
                    'flagged': 'false',
                    'disable_commenting': 'true',
                    'valid_to': '',
                    'retired': '',
                    'u_kc_object_id': '',
                    'u_download_url': '',
                    'display_attachments': 'false',
                    'latest': 'true',
                    'summary': {
                        'link': 'https://support.opentext.com/api/now/table/kb_knowledge_summary/410fbd4547651910ab0a9ed7536d4356',
                        'value': '410fbd4547651910ab0a9ed7536d4356'
                    },
                    'sys_view_count': '2',
                    'revised_by': {
                        'link': 'https://support.opentext.com/api/now/table/sys_user/6fea35401ba3811461a7a8e22a4bcb59',
                        'value': '6fea35401ba3811461a7a8e22a4bcb59'
                    },
                    'article_type': 'text',
                    'u_internal_class': '',
                    'u_kc_parent_id': '',
                    'confidence': 'validated',
                    'sys_mod_count': '4',
                    'sys_tags': '',
                    'replacement_article': '',
                    'taxonomy_topic': '',
                    'u_application': '52609e001b3a891061a7a8e22a4bcb96',
                    'view_as_allowed': 'true',
                    'ownership_group': {
                        'link': 'https://support.opentext.com/api/now/table/sys_user_group/9a1f66a0473d6d10b6a6778bd36d4375',
                        'value': '9a1f66a0473d6d10b6a6778bd36d4375'
                    },
                    'category': '',
                    'kb_category': {
                        'link': 'https://support.opentext.com/api/now/table/kb_category/d0144f5edb21781068cfd6c4e2961992',
                        'value': 'd0144f5edb21781068cfd6c4e2961992'
                    },
                    'governance': 'experience'
                },
                ...
            ]
        """

        return self.get_table(
            table_name=table_name,  # derived from table kb_knowledge
            query=query,
            fields=fields,
            limit=limit,
            offset=offset,
            error_string="Cannot get knowledge base articles; ",
        )

    # end method definition

    def make_file_names_unique(self, file_list: list):
        """Make file names unique if required. The mutable
           list is changed "in-place".

        Args:
            file_list (list): list of attachments as dictionaries
                              with "sys_id" and "file_name" keys.
        """

        # Dictionary to keep track of how many times each file name has been encountered
        name_count = {}

        # Iterate through the list of dictionaries
        for file_info in file_list:
            original_name = file_info["file_name"]
            name, ext = os.path.splitext(original_name)

            # Initialize count if this is the first time the name is encountered
            if original_name not in name_count:
                name_count[original_name] = 0

            # Generate a unique file name if the original name has been seen before
            if name_count[original_name] > 0:
                new_name = f"{name} ({name_count[original_name]:02}){ext}"
                # Check if this new name already exists in the list to avoid collisions.
                # If it does, increment the suffix number until a unique name is found.
                while any(f["file_name"] == new_name for f in file_list):
                    name_count[original_name] += 1
                    new_name = f"{name} ({name_count[original_name]:02}){ext}"
                file_info["file_name"] = new_name

            # Increment the count for this file name
            name_count[original_name] += 1

    # end method definition

    def get_article_attachments(self, article: dict) -> list | None:
        """Get a list of attachments for an article

        Args:
            article (dict): Article information

        Returns:
            list | None: list of attachments
        """

        article_sys_id = article["sys_id"]
        article_number = article["number"]

        request_header = self.request_header()
        request_url = self.config()["attachmentsUrl"]

        params = {
            "sysparm_query": "table_sys_id={}".format(article_sys_id),
            "sysparm_fields": "sys_id,file_name",
        }

        try:
            response = self._session.get(
                url=request_url, headers=request_header, params=params
            )
            data = self.parse_request_response(response)
            attachments = data.get("result", [])
            if not attachments:
                logger.debug(
                    "Knowledge base article -> %s does not have attachments!",
                    article_number,
                )
                return []
            else:
                logger.info(
                    "Knowledge base article -> %s has %s attachments.",
                    article_number,
                    len(attachments),
                )
                return attachments

        except HTTPError as http_err:
            logger.error("HTTP error occurred -> %s!", str(http_err))
        except RequestException as req_err:
            logger.error("Request error occurred -> %s!", str(req_err))
        except Exception as err:
            logger.error("An error occurred -> %s!", str(err))

        return None

    # end method definition

    def download_attachments(
        self,
        article: dict,
        skip_existing: bool = True,
    ) -> bool:
        """Download the attachments of a Knowledge Base Article (KBA) in ServiceNow.

        Args:
            article (dict): dictionary holding the Service Now article data
            skip_existing (bool, optional): skip download if file has been downloaded before

        Returns:
            bool: True = success, False = failure
        """

        article_number = article["number"]

        attachments = self.get_article_attachments(article)

        if not attachments:
            logger.debug(
                "Knowledge base article -> %s does not have attachments to download!",
                article_number,
            )
            article["has_attachments"] = False
            return False
        else:
            logger.info(
                "Knowledge base article -> %s has %s attachments to download...",
                article_number,
                len(attachments),
            )
            article["has_attachments"] = True

        # Service Now can have multiple files with the same name - we need to
        # resolve this for Extended ECM:
        self.make_file_names_unique(attachments)

        base_dir = os.path.join(self._download_dir, article_number)

        # save download dir for later use in bulkDocument processing...
        article["download_dir"] = base_dir

        article["download_files"] = []
        article["download_files_ids"] = []

        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        for attachment in attachments:
            file_path = os.path.join(base_dir, attachment["file_name"])

            if os.path.exists(file_path) and skip_existing:
                logger.info(
                    "File -> %s has been downloaded before. Skipping download...",
                    file_path,
                )

                # we need to add file_name and sys_id in the list of files and for later use in bulkDocument processing...
                article["download_files"].append(attachment["file_name"])
                article["download_files_ids"].append(attachment["sys_id"])
                continue
            attachment_download_url = (
                self.config()["attachmentDownloadUrl"]
                + "/"
                + attachment["sys_id"]
                + "/file"
            )
            try:
                logger.info(
                    "Downloading attachment file -> '%s' for article -> %s from ServiceNow...",
                    file_path,
                    article_number,
                )

                attachment_response = self._session.get(
                    attachment_download_url, stream=True
                )
                attachment_response.raise_for_status()

                with open(file_path, "wb") as file:
                    for chunk in attachment_response.iter_content(chunk_size=8192):
                        file.write(chunk)

                # we build a list of filenames and ids.
                # the ids we want to use as nicknames later on
                article["download_files"].append(attachment["file_name"])
                article["download_files_ids"].append(attachment["sys_id"])

            except HTTPError as e:
                logger.error(
                    "Failed to download -> '%s' using url -> %s; error -> %s",
                    attachment["file_name"],
                    attachment_download_url,
                    str(e),
                )

        return True

    # end method definition

    def load_articles(self, table_name: str, query: str | None) -> bool:
        """Main method to load ServiceNow articles in a Data Frame and
           download the attchments.

        Args:
            query (str): Filter criteria for the articles.

        Returns:
            bool: True = Success, False = Failure
        """

        total_count = self.get_table_count(table_name=table_name, query=query)

        logger.info(
            "Total number of Knowledge Base Articles (KBA) -> %s", str(total_count)
        )

        if total_count == 0:
            logger.info(
                "Query does not return any value from ServiceNow table -> '%s'. Finishing.",
                table_name,
            )
            return True

        number = self._thread_number

        if total_count >= number:
            partition_size = total_count // number
            remainder = total_count % number
        else:
            partition_size = total_count
            remainder = 0
            number = 1

        logger.info(
            "Processing -> %s Knowledge Base Articles (KBA), table name -> '%s', thread number -> %s, partition size -> %s",
            str(total_count),
            table_name,
            number,
            partition_size,
        )

        threads = []

        current_offset = 0
        for i in range(number):
            current_partition_size = partition_size + (1 if i < remainder else 0)
            thread = threading.Thread(
                name=f"load_articles_{i+1:02}",
                target=self.thread_wrapper,
                args=(
                    self.load_articles_worker,
                    table_name,
                    query,
                    current_partition_size,
                    current_offset,
                ),
            )
            thread.start()
            threads.append(thread)
            current_offset += current_partition_size

        for thread in threads:
            thread.join()

        return True

    # end method definition

    def load_articles_worker(
        self, table_name: str, query: str, partition_size: int, partition_offset: int
    ) -> None:
        """Worker Method for multi-threading.

        Args:
            query (str): Query to select the relevant KBA.
            partition_size (int): Total size of the partition assigned to this thread.
            partition_offset (int): Starting offset for the KBAs this thread is processing.
        """

        logger.info(
            "Start processing KBAs in range from -> %s to -> %s from table -> '%s'...",
            partition_offset,
            partition_offset + partition_size,
            table_name,
        )

        # We cannot retrieve all KBAs in one go if the partition size is too big (> 100)
        # So we define "limit" as the maximum number of KBAs we want to retrieve for one REST call.
        # This should be a reasonable number to avoid timeouts. We also need to make sure
        # the limit is not bigger than the the partition size:
        limit = 100 if partition_size > 100 else partition_size

        for offset in range(partition_offset, partition_offset + partition_size, limit):
            articles = self.get_table(
                table_name=table_name, query=query, limit=limit, offset=offset
            )
            logger.info(
                "Retrieved a list of %s KBAs starting at offset -> %s to process.",
                str(len(articles)),
                offset,
            )
            for article in articles:
                logger.info("Processing KBA -> %s...", article["number"])
                article["source_table"] = table_name
                self.load_article(article)

        logger.info(
            "Finished processing KBAs in range from -> %s to -> %s from table -> '%s'.",
            partition_offset,
            partition_offset + partition_size,
            table_name,
        )

    # end method definition

    def load_article(self, article: dict, skip_existing_downloads: bool = True):
        """Process a single KBA: download attachments (if any), add additional
           keys / values to the article from other ServiceNow tables,
           and finally add the KBA to the Data Frame.

        Args:
            article (dict): Dictionary inclusing all fields of
                            a single KBA. This is a mutable variable
                            that gets modified by this method!

        Side effect:
            The article dict is modified with by adding additional key / value
            pairs (these can be used in the payload files!):

            * kb_category_name - the readable name of the ServiceNow category
            * kb_knowledge_base_name - the readable name of the ServiceNow KnowledgeBase
            * related_product_names - this list includes the related product names for the article
            * u_product_line_names - this list includes the related product line names for the article
            * u_sub_product_line_names - this list includes the related sub product line names for the article
            * u_application_names - this list includes the related application names for the article
            * u_application_versions - this list includes the related application versions for the article
            * u_application_version_sets - this table includes lines for each application + version. Sub items:
              - u_product_model - name of the application
              - u_version_name - name of the version - e.g. 24.4

        """

        _ = self.download_attachments(
            article=article, skip_existing=skip_existing_downloads
        )

        #
        # Add additional columns from related ServiceNow tables:
        #

        if "kb_category" in article and article["kb_category"]:
            category_key = article.get("kb_category")["value"]
            category_table_name = SN_TABLE_CATEGORIES
            category = self.get_object(
                table_name=category_table_name, sys_id=category_key
            )
            if category:
                article["kb_category_name"] = self.get_result_value(
                    response=category, key="full_category"
                )
            else:
                logger.warning(
                    "Article -> %s has no category value!", article["number"]
                )
                article["kb_category_name"] = ""
        else:
            logger.warning(
                "Article -> %s has no value for category!", article["number"]
            )
            article["kb_category_name"] = ""

        knowledge_base_key = article.get("kb_knowledge_base")["value"]
        knowledge_base_table_name = SN_TABLE_KNOWLEDGE_BASES
        knowledge_base = self.get_object(
            table_name=knowledge_base_table_name, sys_id=knowledge_base_key
        )
        if knowledge_base:
            article["kb_knowledge_base_name"] = self.get_result_value(
                response=knowledge_base, key="title"
            )
        else:
            logger.warning(
                "Article -> %s has no value for Knowledge Base!",
                article["number"],
            )
            article["kb_knowledge_base_name"] = ""

        related_product_names = []
        if article.get("related_products", None):
            related_product_keys = article.get("related_products").split(",")
            for related_product_key in related_product_keys:
                related_product = self.get_object(
                    table_name=SN_TABLE_RELATED_PRODUCTS, sys_id=related_product_key
                )
                if related_product:
                    related_product_name = self.get_result_value(
                        response=related_product, key="name"
                    )
                    logger.debug(
                        "Found related Product -> '%s' (%s)",
                        related_product_name,
                        related_product_key,
                    )
                    related_product_names.append(related_product_name)
                    # Extended ECM can only handle a maxiumum of 50 line items:
                    if len(related_product_names) == 49:
                        logger.info(
                            "Reached maximum of 50 multi-value items for related Products of article -> %s",
                            article["number"],
                        )
                        break
                else:
                    logger.warning(
                        "Article -> %s: Cannot lookup related Product name in table -> '%s' with ID -> %s",
                        article["number"],
                        SN_TABLE_RELATED_PRODUCTS,
                        related_product_key,
                    )
        else:
            logger.warning(
                "Article -> %s has no value related Products!",
                article["number"],
            )
        article["related_product_names"] = related_product_names

        product_line_names = []
        if article.get("u_product_line", None):
            product_line_keys = article.get("u_product_line").split(",")
            product_line_table = SN_TABLE_PRODUCT_LINES
            for product_line_key in product_line_keys:
                product_line = self.get_object(
                    table_name=product_line_table, sys_id=product_line_key
                )
                if product_line:
                    product_line_name = self.get_result_value(
                        response=product_line, key="name"
                    )
                    logger.debug(
                        "Found related Product Line -> '%s' (%s)",
                        product_line_name,
                        product_line_key,
                    )
                    product_line_names.append(product_line_name)
                    # Extended ECM can only handle a maxiumum of 50 line items:
                    if len(product_line_names) == 49:
                        logger.info(
                            "Reached maximum of 50 multi-value items for related Product Lines of article -> %s",
                            article["number"],
                        )
                        break
                else:
                    logger.warning(
                        "Article -> %s: Cannot lookup related Product Line name in table -> '%s' with ID -> %s",
                        article["number"],
                        product_line_table,
                        product_line_key,
                    )
        else:
            logger.warning(
                "Article -> %s has no value for related Product Lines!",
                article["number"],
            )
        article["u_product_line_names"] = product_line_names

        sub_product_line_names = []
        if article.get("u_sub_product_line", None):
            sub_product_line_keys = article.get("u_sub_product_line").split(",")
            sub_product_line_table = SN_TABLE_PRODUCT_LINES
            for sub_product_line_key in sub_product_line_keys:
                sub_product_line = self.get_object(
                    table_name=sub_product_line_table, sys_id=sub_product_line_key
                )
                if sub_product_line:
                    sub_product_line_name = self.get_result_value(
                        response=sub_product_line, key="name"
                    )
                    logger.debug(
                        "Found related Sub Product Line -> '%s' (%s)",
                        sub_product_line_name,
                        sub_product_line_key,
                    )
                    sub_product_line_names.append(sub_product_line_name)
                    # Extended ECM can only handle a maxiumum of 50 line items:
                    if len(sub_product_line_names) == 49:
                        logger.info(
                            "Reached maximum of 50 multi-value items for related Sub Product Lines of article -> %s",
                            article["number"],
                        )
                        break
                else:
                    logger.warning(
                        "Article -> %s: Cannot lookup related Sub Product Line name in table -> '%s' with ID -> %s",
                        article["number"],
                        sub_product_line_table,
                        sub_product_line_key,
                    )
        else:
            logger.warning(
                "Article -> %s has no value for related Sub Product Lines!",
                article["number"],
            )
        article["u_sub_product_line_names"] = sub_product_line_names

        application_names = []
        if article.get("u_application", None):
            application_keys = article.get("u_application").split(",")
            application_table_name = SN_TABLE_PRODUCT_LINES
            for application_key in application_keys:
                application = self.get_object(
                    table_name=application_table_name, sys_id=application_key
                )
                if application:
                    application_name = self.get_result_value(
                        response=application, key="name"
                    )
                    logger.debug(
                        "Found related Application -> '%s' (%s)",
                        application_name,
                        application_key,
                    )
                    application_names.append(application_name)
                    # Extended ECM can only handle a maxiumum of 50 line items:
                    if len(application_names) == 49:
                        logger.info(
                            "Reached maximum of 50 multi-value items for related Applications of article -> %s",
                            article["number"],
                        )
                        break
                else:
                    logger.warning(
                        "Article -> %s: Cannot lookup related Application name in table -> '%s' with ID -> %s",
                        article["number"],
                        application_table_name,
                        application_key,
                    )
        else:
            logger.warning(
                "Article -> %s has no value for related Applications!",
                article["number"],
            )
        article["u_application_names"] = application_names

        application_versions = []
        application_version_sets = []
        if article.get("u_application_version", None):
            application_version_keys = article.get("u_application_version").split(",")
            for application_version_key in application_version_keys:
                # Get the version object from ServiceNow. It includes both,
                # the application version number and the application name:
                application_version = self.get_object(
                    table_name=SN_TABLE_PRODUCT_VERSIONS,
                    sys_id=application_version_key,
                )
                if application_version:
                    application_version_name = self.get_result_value(
                        response=application_version, key="u_version_name"
                    )
                    logger.debug(
                        "Found related Application Version -> '%s' (%s)",
                        SN_TABLE_PRODUCT_LINES,
                        application_version_key,
                    )

                    application_versions.append(application_version_name)

                    # Lookup application name of version and fill the set

                    application_key = self.get_result_value(
                        response=application_version, key="u_product_model"
                    )

                    if application_key:
                        # u_applicatio_model has a substructure like this:
                        # {
                        #   'link': 'https://support.opentext.com/api/now/table/u_ot_product_model/9b2dcea747f6d910ab0a9ed7536d4364',
                        #   'value': '9b2dcea747f6d910ab0a9ed7536d4364'
                        # }
                        # We want the value:
                        application_key = application_key.get("value")

                    if application_key:
                        application = self.get_object(
                            table_name=SN_TABLE_PRODUCT_LINES,
                            sys_id=application_key,
                        )

                        application_name = self.get_result_value(
                            response=application, key="name"
                        )

                        if application_name:
                            application_version_sets.append(
                                {
                                    # "Application": application_name,
                                    # "Version": application_version_name,
                                    "u_product_model": application_name,
                                    "u_version_name": application_version_name,
                                }
                            )

                    # Extended ECM can only handle a maxiumum of 50 line items:
                    if len(application_versions) == 49:
                        logger.info(
                            "Reached maximum of 50 multi-value items for related Application Version of article -> %s",
                            article["number"],
                        )
                        break
                else:
                    logger.warning(
                        "Article -> %s: Cannot lookup related Application Version in table -> '%s' with ID -> %s",
                        article["number"],
                        SN_TABLE_PRODUCT_VERSIONS,
                        application_version_key,
                    )
        else:
            logger.warning(
                "Article -> %s has no value for related Application Version!",
                article["number"],
            )
        # Convert to list and set to remove duplicates:
        article["u_application_versions"] = list(set(application_versions))

        # This set maps the applications and the versions (table-like structure)
        article["u_application_version_sets"] = application_version_sets

        # Now we add the article to the Pandas Data Frame in the Data class:
        with self._data.lock():
            self._data.append(article)

    # end method definition

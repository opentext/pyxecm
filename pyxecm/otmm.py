"""
OTMM Module to interact with the OpenText Media Management API
See: 

Class: OTMM
Methods:

__init__ : class initializer
config : Returns config data set
get_data: Get the Data object that holds all processed Media Management base Assets
credentials: Returns the token data
request_header: Returns the request header for ServiceNow API calls
parse_request_response: Parse the REST API responses and convert
                        them to Python dict in a safe way
exist_result_item: Check if an dict item is in the response
                   of the ServiceNow API call
get_result_value: Check if a defined value (based on a key) is in the ServiceNow API response

authenticate : Authenticates at ServiceNow API
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

from json import JSONDecodeError
import os
import logging
import urllib.parse
import threading
import traceback

import requests
from requests.exceptions import HTTPError, RequestException

from pyxecm.helper.data import Data

logger = logging.getLogger("pyxecm.otmm")

REQUEST_HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

REQUEST_TIMEOUT = 60

ASSET_BASE_PATH = "/tmp/mediaassets"


class OTMM:
    """Used to retrieve and automate data extraction from OTMM."""

    _config: dict
    _access_token = None
    _data: Data = None
    _thread_number = 3
    _download_dir = ""
    _business_unit_exclusions = None
    _product_exclusions = None

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        client_id: str,
        client_secret: str,
        thread_number: int,
        download_dir: str,
        business_unit_exclusions: list | None = None,
        product_exclusions: list | None = None,
    ):

        # Initialize otcs_config as an empty dictionary
        otmm_config = {}

        # Store the credentials and parameters in a config dictionary:
        otmm_config["baseUrl"] = base_url
        otmm_config["username"] = username
        otmm_config["password"] = password
        otmm_config["clientId"] = client_id
        otmm_config["clientSecret"] = client_secret

        otmm_config["restUrl"] = otmm_config["baseUrl"] + "/otmmapi/v6"
        otmm_config["tokenUrl"] = otmm_config["restUrl"] + "/sessions/oauth2/token"
        otmm_config["domainUrl"] = otmm_config["restUrl"] + "/lookupdomains"
        otmm_config["assetsUrl"] = otmm_config["restUrl"] + "/assets"
        otmm_config["searchUrl"] = otmm_config["restUrl"] + "/search/text"

        self._config = otmm_config

        self._session = requests.Session()

        self._data = Data()

        self._thread_number = thread_number

        self._download_dir = download_dir

        self._business_unit_exclusions = business_unit_exclusions
        self._product_exclusions = product_exclusions

    # end method definition

    def thread_wrapper(self, target, *args, **kwargs):
        """Function to wrap around threads to catch exceptions during exection"""
        try:
            target(*args, **kwargs)
        except Exception as e:
            thread_name = threading.current_thread().name
            logger.error("Thread '%s': failed with exception -> %s", thread_name, e)
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
        """Get the Data object that holds all processed Media Management base Assets

        Returns:
            Data: Datastructure with all processed assets.
        """

        return self._data

    # end method definition

    def authenticate(self) -> str | None:
        """Authenticate at OTMM with client ID and client secret or with basic authentication."""

        request_url = self.config()["tokenUrl"]
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {
            "username": self.config()["username"],
            "password": self.config()["password"],
            "grant_type": "password",
            "client_id": self.config()["clientId"],
            "client_secret": self.config()["clientSecret"],
        }

        try:
            response = self._session.post(
                request_url,
                headers=headers,
                data=urllib.parse.urlencode(payload),
            )
            response.raise_for_status()

            self._access_token = (
                response.json().get("token_info").get("oauth_token").get("accessToken")
            )
            self._session.headers.update(
                {"Authorization": f"Bearer {self._access_token}"}
            )

            return self._access_token

        except requests.exceptions.HTTPError as http_err:
            logger.error("HTTP error occurred: %s", http_err)
        except requests.exceptions.ConnectionError as conn_err:
            logger.error("Connection error occurred: %s", conn_err)
        except requests.exceptions.Timeout as timeout_err:
            logger.error("Timeout error occurred: %s", timeout_err)
        except requests.exceptions.RequestException as req_err:
            logger.error("Request error occurred: %s", req_err)
        except Exception as e:
            logger.error("An unexpected error occurred: %s", e)

        return None

    # end method definition

    def get_products(self, domain: str = "OTMM.DOMAIN.OTM_PRODUCT") -> dict:
        """Get a dictionary with product names (keys) and IDs (values)

        Args:
            domain (str, optional): Domain. Defaults to "OTMM.DOMAIN.OTM_PRODUCT".
        Returns:
            dict: Dictionary of all known products.
        """

        lookup_products = self.lookup_domains(domain)

        result = {}
        for product in lookup_products:
            result[product.get("display_value")] = product.get("field_value").get(
                "value"
            )

        return result

    # end method definition

    def get_business_units(
        self, domain: str = "OTMM.DOMAIN.OTM_BUSINESS_UNIT.LU"
    ) -> dict:
        """Get a dictionary with product names (keys) and IDs (values)

        Args:
            domain (str, optional): Domain. Defaults to "OTMM.DOMAIN.OTM_BUSINESS_UNIT.LU".

        Returns:
            dict: Dictionary of all known business units.
        """

        lookup_bus = self.lookup_domains(domain)
        result = {}
        for bu in lookup_bus:
            result[bu.get("display_value")] = bu.get("field_value").get("value")

        return result

    # end method definition

    def lookup_domains(self, domain: str):
        """Lookup domain values in a given OTMM domain

        Args:
            domain (str): name / identifier of the domain.

        Returns:
            _type_: _description_
        """

        request_url = self.config()["domainUrl"] + "/" + domain

        try:
            response = self._session.get(
                request_url,
            )

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_err:
            logger.error("HTTP error occurred: %s", http_err)
        except requests.exceptions.ConnectionError as conn_err:
            logger.error("Connection error occurred: %s", conn_err)
        except requests.exceptions.Timeout as timeout_err:
            logger.error("Timeout error occurred: %s", timeout_err)
        except requests.exceptions.RequestException as req_err:
            logger.error("Request error occurred: %s", req_err)
        except Exception as e:
            logger.error("An unexpected error occurred: %s", e)

        response = (
            response.json()
            .get("lookup_domain_resource")
            .get("lookup_domain")
            .get("domainValues")
        )

        return response

    # end method definition

    def get_asset(self, asset_id: str) -> dict:
        """Get an asset based on its ID

        Args:
            asset_id (str): Asset ID

        Returns:
            dict: dictionary with asset data
        """

        request_url = self.config()["assetsUrl"] + "/" + asset_id

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            response = self._session.get(
                request_url,
                headers=headers,
            )

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_err:
            logger.error("HTTP error occurred: %s", http_err)
            return None
        except requests.exceptions.ConnectionError as conn_err:
            logger.error("Connection error occurred: %s", conn_err)
            return None
        except requests.exceptions.Timeout as timeout_err:
            logger.error("Timeout error occurred: %s", timeout_err)
            return None
        except requests.exceptions.RequestException as req_err:
            logger.error("Request error occurred: %s", req_err)
            return None
        except Exception as e:
            logger.error("An unexpected error occurred: %s", e)
            return None

        return response.json()

    # end method definition

    def get_business_unit_assets(
        self, bu_id: int, offset: int = 0, limit: int = 200
    ) -> list | None:
        """Get all Media Assets for a given Business Unit (ID) that are NOT related to a product.

        Args:
            bu_id (int): Identifier of the Business Unit.
            offset (int, optional): Result pagination. Starting ID. Defaults to 0.
            limit (int, optional): Result pagination. Page length. Defaults to 200.

        Returns:
            dict: Search Results
        """

        payload = {
            "load_type": ["metadata"],
            "load_multilingual_values": ["true"],
            "level_of_detail": ["full"],
            "after": offset,
            "limit": limit,
            "multilingual_language_code": ["en_US"],
            "search_config_id": ["3"],
            "preference_id": ["ARTESIA.PREFERENCE.GALLERYVIEW.DISPLAYED_FIELDS"],
            "metadata_to_return": ["ARTESIA.FIELD.TAG"],
            "facet_restriction_list": '{"facet_restriction_list":{"facet_field_restriction":[{"type":"com.artesia.search.facet.FacetSimpleFieldRestriction","facet_generation_behavior":"EXCLUDE","field_id":"PRODUCT_CHAR_ID","value_list":[null]}]}}',
            "search_condition_list": [
                '{"search_condition_list":{"search_condition":[{"type":"com.artesia.search.SearchTabularCondition","metadata_table_id":"OTMM.FIELD.BUSINESS_UNIT.TAB","tabular_field_list":[{"type":"com.artesia.search.SearchTabularFieldCondition","metadata_field_id":"OTMM.COLUMN.BUSINESS_UNIT.TAB","relational_operator_id":"ARTESIA.OPERATOR.CHAR.CONTAINS","value":"'
                + str(bu_id)
                + '","left_paren":"(","right_paren":")"}]}]}}'
            ],
        }

        flattened_data = {
            k: v if not isinstance(v, list) else ",".join(v) for k, v in payload.items()
        }

        search_result = self.search_assets(flattened_data)

        if not search_result or not "search_result_resource" in search_result:
            logger.error("No assets found via search!")
            return None
        search_result = search_result.get("search_result_resource")

        hits = search_result["search_result"]["hit_count"]
        hits_total = search_result["search_result"]["total_hit_count"]

        asset_list = search_result.get("asset_list", None)

        hits_remaining = hits_total - hits

        while hits_remaining > 0:
            flattened_data["after"] += hits
            search_result = self.search_assets(flattened_data)

            if not search_result or not "search_result_resource" in search_result:
                break

            search_result = search_result.get("search_result_resource")

            hits = search_result["search_result"]["hit_count"]
            hits_remaining = hits_remaining - hits

            asset_list += search_result.get("asset_list", [])

        return asset_list

    # end method definition

    def get_product_assets(
        self, product_id: int, offset: int = 0, limit: int = 200
    ) -> list | None:
        """Get all Media Assets for a given product (ID).

        Args:
            product_id (int): Identifier of the product.
            offset (int, optional): Result pagination. Starting ID. Defaults to 0.
            limit (int, optional): Result pagination. Page length. Defaults to 200.

        Returns:
            dict: Search Results
        """

        payload = {
            "load_type": ["metadata"],
            "load_multilingual_values": ["true"],
            "level_of_detail": ["full"],
            "after": offset,
            "limit": limit,
            "multilingual_language_code": ["en_US"],
            "search_config_id": ["3"],
            "preference_id": ["ARTESIA.PREFERENCE.GALLERYVIEW.DISPLAYED_FIELDS"],
            "metadata_to_return": ["ARTESIA.FIELD.TAG"],
            "search_condition_list": [
                '{"search_condition_list":{"search_condition":[{"type":"com.artesia.search.SearchTabularCondition","metadata_table_id":"OTM.TABLE.PRODUCT_TABLE_FIELD","tabular_field_list":[{"type":"com.artesia.search.SearchTabularFieldCondition","metadata_field_id":"PRODUCT_CHAR_ID","relational_operator_id":"ARTESIA.OPERATOR.CHAR.CONTAINS","value":"'
                + str(product_id)
                + '","left_paren":"(","right_paren":")"}]}]}}'
            ],
        }

        flattened_data = {
            k: v if not isinstance(v, list) else ",".join(v) for k, v in payload.items()
        }

        search_result = self.search_assets(flattened_data)

        if not search_result or not "search_result_resource" in search_result:
            logger.error("No assets found via search!")
            return None
        search_result = search_result.get("search_result_resource")

        hits = search_result["search_result"]["hit_count"]
        hits_total = search_result["search_result"]["total_hit_count"]

        asset_list = search_result.get("asset_list", None)

        hits_remaining = hits_total - hits

        while hits_remaining > 0:
            flattened_data["after"] += hits
            search_result = self.search_assets(flattened_data)

            if not search_result or not "search_result_resource" in search_result:
                break

            search_result = search_result.get("search_result_resource")

            hits = search_result["search_result"]["hit_count"]
            hits_remaining = hits_remaining - hits

            asset_list += search_result.get("asset_list", [])

        return asset_list

    # end method definition

    def download_asset(
        self,
        asset_id: str,
        asset_name: str,
        download_url: str = "",
        skip_existing: bool = True,
    ) -> bool:
        """Download a given Media Asset

        Args:
            asset_id (str): ID of the asset to download
            asset_name (str): Name of the assets - becomes the file name.
            download_url (str, optiona): URL to download the asset (optional).

        Returns:
            bool: True = success, False = failure
        """
        #        url = f"{self.base_url}/assets/v1/{asset_id}/download"

        if download_url:
            request_url = download_url
        else:
            request_url = self.config()["assetsUrl"] + "/" + asset_id + "/contents"

        file_name = os.path.join(self._download_dir, asset_id)

        if os.path.exists(file_name):
            if skip_existing:
                logger.debug(
                    "OpenText Media Management asset has been downloaded before skipping download -> '%s' (%s) to -> %s...",
                    asset_name,
                    asset_id,
                    file_name,
                )
                return True
            else:
                logger.debug(
                    "OpenText Media Management asset has been downloaded before. Update download -> '%s' (%s) to -> %s...",
                    asset_name,
                    asset_id,
                    file_name,
                )
                os.remove(file_name)

        try:
            if not os.path.exists(self._download_dir):
                # Create the directory
                os.makedirs(self._download_dir)

            logger.info(
                "Downloading OpenText Media Management asset -> '%s' (%s) to -> %s...",
                asset_name,
                asset_id,
                file_name,
            )
            response = self._session.get(request_url, stream=True)
            response.raise_for_status()
            with open(file_name, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        except HTTPError as http_err:
            logger.error("HTTP error occurred -> %s!", str(http_err))
        except RequestException as req_err:
            logger.error("Request error occurred -> %s!", str(req_err))
        except Exception as err:
            logger.error("An error occurred -> %s!", str(err))

        return False

    # end method definition

    def search_assets(self, payload: dict):
        """Search an asset based on the given parameters / criterias.

        Args:
            payload (dict): in the format of:
                            payload = {
                                "PRODUCT_CHAR_ID": "Extended ECM for Engineering",
                                "BUSINESS_AREA_CHAR_ID": "Content",
                                "keyword_query": "*",
                                "limit": "5",
                            }

        Returns:
            _type_: JSON search results
        """

        request_url = self.config()["searchUrl"]

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        encoded_payload = urllib.parse.urlencode(payload, safe="/:")

        try:
            response = self._session.post(
                request_url,
                headers=headers,
                data=encoded_payload,
            )

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_err:
            logger.error("HTTP error occurred: %s", http_err)
        except requests.exceptions.ConnectionError as conn_err:
            logger.error("Connection error occurred: %s", conn_err)
        except requests.exceptions.Timeout as timeout_err:
            logger.error("Timeout error occurred: %s", timeout_err)
        except requests.exceptions.RequestException as req_err:
            logger.error("Request error occurred: %s", req_err)
        except Exception as e:
            logger.error("An unexpected error occurred: %s", e)

        return response.json()

    # end method definition

    def get_asset_metadata(self, asset_id: str) -> dict:
        """Retrieve metadata of an asset based on the given parameters / criterias.

        Args:
            asset_id (str): asset_id of the asset to query

        Returns:
            dict: Metadata information as dict with values as list

                  example:
                  {
                    'OTMM.CUSTOM.FIELD_TITLE': [],
                    'OTMM.CUSTOM.FIELD_DESCRIPTION': [],
                    'OTMM.CUSTOM.FIELD_KEYWORDS': [],
                    'CONTENT_TYPE_COMBO_CHAR_ID': [],
                    'OTM.TABLE.APPROVED_USAGE_FIELD': [],
                    'OTMM.FIELD.RESOURCE_LIBRARY.TAB': [],
                    'LANGUAGE_COMBO_CHAR_ID': [],
                    'OTMM.CUSTOM.FIELD_PART_NUMBER': [],
                    'OTMM.FIELD.BUSINESS_UNIT.TAB': ['Content'],
                    'OTM.TABLE.PRODUCT_TABLE_FIELD': ['Vendor Invoice Management for SAP'],
                    'OTM.TABLE.INDUSTRY_TABLE_FIELD': [],
                    'OTMM.CUSTOM.FIELD_URL': [],
                    'OTMM.CUSTOM.FIELD_PREVIOUS_URL': [],
                    'OTMM.CUSTOM.FIELD_CONTENT_OWNER': [],
                    'OTMM.CUSTOM.FIELD_EMAIL': [],
                    'OTMM.CUSTOM.FIELD_JOB_NUMBER': [],
                    'OTM.TABLE.BUSINESS_AREA_TABLE_FIELD': [],
                    'OTM.TABLE.JOURNEY_TABLE_FIELD': ['Buy', 'Try', 'Learn'],
                    'OTMM.FIELD.PERSONA.TAB': [],
                    'OTMM.FIELD.SERVICES.TAB': [],
                    'OTMM.FIELD.REGION.TAB': [],
                    'OTMM.FIELD.PURPOSE.TAB': [],
                    'AODA_CHAR_ID': [],
                    'REVIEW_CADENCE_CHAR_ID': [],
                    'CONTENT_CREATED_DATE_ID': [],
                    'ARTESIA.FIELD.EXPIRATION DATE': [],
                    'OTMM.CUSTOM.FIELD_REAL_COMMENTS': []
                  }
        """

        request_url = self.config()["assetsUrl"] + f"/{asset_id}"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        params = {
            "load_type": "custom",
            "level_of_detail": "slim",
            "data_load_request": '{"data_load_request":{"load_multilingual_field_values":"true","load_subscribed_to":"true","load_asset_content_info":"true","load_metadata":"true","load_inherited_metadata":"true","load_thumbnail_info":"true","load_preview_info":"true", "load_pdf_preview_info":"true", "load_3d_preview_info" : "true","load_destination_links":"true", "load_security_policies":"true","load_path":"true","load_deep_zoom_info":"true"}}',
        }

        try:
            response = self._session.get(request_url, headers=headers, params=params)

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_err:
            logger.error("HTTP error occurred: %s", http_err)
        except requests.exceptions.ConnectionError as conn_err:
            logger.error("Connection error occurred: %s", conn_err)
        except requests.exceptions.Timeout as timeout_err:
            logger.error("Timeout error occurred: %s", timeout_err)
        except requests.exceptions.RequestException as req_err:
            logger.error("Request error occurred: %s", req_err)
        except Exception as e:
            logger.error("An unexpected error occurred: %s", e)

        # Read Metadata from nested structure
        try:
            metadata = (
                response.json()
                .get("asset_resource", {})
                .get("asset", {})
                .get("metadata", {})
                .get("metadata_element_list", [])[0]
                .get("metadata_element_list", [])
            )
        except JSONDecodeError:
            logger.error("Cannot decode JSON response for assset_id -> %s", asset_id)
            return {}

        # Generate empty result dict
        result = {}

        # Extract Metadata fields with values as list
        for data in metadata:
            index = data.get("id").replace(" ", "").replace(".", "_")

            try:
                result[index] = data.get("value").get("value").get("value")
            except AttributeError:

                infos = []
                for element in data.get("metadata_element_list", []):
                    for value in element.get("values", []):
                        infos.append(value.get("value").get("display_value"))

                result[index] = infos
        return result

    # end method definition

    def load_assets(
        self,
        load_products: bool = True,
        load_business_units: bool = True,
        download_assets: bool = True,
    ) -> bool:
        """Load all Media Assets for Products and Business Units

        Args:
            load_products (bool, optional): If true load assets on Business Unit level. Defaults to True.
            load_business_units (bool, optional): If true load assets on Product level. Defaults to True.
            download_assets (bool, optional): Should assets been downloaded. Defaults to True.

        Returns:
            bool: True = Success, False = Failure

        Example Asset:
        {
            'access_control_descriptor': {
                'permissions_map': {...}
            },
            'asset_content_info': {
                'master_content': {...}
            },
            'asset_id': '68fe5a6423fd317fdf87e83bc8cde736d4df27bf',
            'asset_lock_state_last_update_date': '2024-09-09T22:02:53Z',
            'asset_lock_state_user_id': '202',
            'asset_state': 'NORMAL',
            'asset_state_last_update_date': '2024-09-09T22:02:53Z',
            'asset_state_user_id': '202',
            'checked_out': False,
            'content_editable': True,
            'content_lock_state_last_update_date': '2024-08-14T00:33:27Z',
            'content_lock_state_user_id': '202',
            'content_lock_state_user_name': 'ajohnson3',
            'content_size': 18474085,
            'content_state': 'NORMAL',
            'content_state_last_update_date': '2024-08-14T00:33:27Z',
            'content_state_user_id': '202',
            'content_state_user_name': 'Amanda Johnson',
            'content_type': 'ACROBAT',
            'creator_id': '202',
            'date_imported': '2024-08-14T00:33:26Z',
            'date_last_updated': '2024-09-09T22:02:53Z',
            'deleted': False,
            'delivery_service_url': 'https://assets.opentext.com/adaptivemedia/rendition?id=68fe5a6423fd317fdf87e83bc8cde736d4df27bf',
            'expired': False,
            'import_job_id': 7764,
            'import_user_name': 'ajohnson3',
            'latest_version': True,
            'legacy_model_id': 104,
            'locked': False,
            'master_content_info': {
                'content_checksum': '45f42d19542af5b6146cbb3927a5490f',
                'content_data': {...},
                'content_kind': 'MASTER',
                'content_manager_id': 'ARTESIA.CONTENT.GOOGLE.CLOUD',
                'content_path': 'data/repository/original/generative-ai-governance-essentials-wp-en_56cbbfe270593ba1a5ab6551d2c8b373469cc1a9.pdf',
                'content_size': 18474085,
                'height': -1,
                'id': '56cbbfe270593ba1a5ab6551d2c8b373469cc1a9',
                'mime_type': 'application/pdf',
                'name': 'generative-ai-governance-essentials-wp-en.pdf',
                'unit_of_size': 'BYTES',
                'url': '/otmmapi/v6/renditions/56cbbfe270593ba1a5ab6551d2c8b373469cc1a9',
                'width': -1
            },
            'metadata_lock_state_user_name': 'ajohnson3',
            'metadata_model_id': 'OTM.MARKETING.MODEL',
            'metadata_state_user_name': 'Amanda Johnson',
            'mime_type': 'application/pdf',
            'name': 'generative-ai-governance-essentials-wp-en.pdf',
            'original_asset_id': '68fe5a6423fd317fdf87e83bc8cde736d4df27bf',
            'product_associations': False,
            'rendition_content': {
                'thumbnail_content': {...},
                'preview_content': {...},
                'pdf_preview_content': {...}
            },
            'subscribed_to': False,
            'thumbnail_content_id': '70aef1a5b5e480337bc115e47443884432c355ff',
            'version': 1
        }
        """

        asset_list = []

        if load_products:

            products = self.get_products()  # dictionary with key = name and value = ID

            if self._product_exclusions:
                logger.info("Excluding products -> %s", str(self._product_exclusions))
                for key in self._product_exclusions:
                    products.pop(
                        key, None
                    )  # pop(key, None) will remove the key if it exists, and do nothing if it doesn't

            for product_name, product_id in products.items():
                if "DO NOT USE" in product_name:
                    continue

                logger.info("Processing product -> '%s'...", product_name)

                assets = self.get_product_assets(product_id)

                if not assets:
                    logger.info("Found no assets for product -> '%s'", product_name)
                    continue

                for asset in assets:
                    asset["workspace_type"] = "Product"
                    asset["workspace_name"] = product_name

                asset_list += [asset for asset in assets if "content_size" in asset]

        if load_business_units:

            business_units = self.get_business_units()

            if self._business_unit_exclusions:
                logger.info(
                    "Excluding business units -> %s",
                    str(self._business_unit_exclusions),
                )
                for key in self._business_unit_exclusions:
                    business_units.pop(
                        key, None
                    )  # pop(key, None) will remove the key if it exists, and do nothing if it doesn't

            for bu_name, bu_id in business_units.items():
                logger.debug(bu_name)
                assets = self.get_business_unit_assets(bu_id)

                if not assets:
                    logger.info("Found no assets for business unit -> '%s'", bu_name)
                    continue

                for asset in assets:
                    asset["workspace_type"] = "Business Unit"
                    asset["workspace_name"] = bu_name

                asset_list += [asset for asset in assets if "content_size" in asset]
            # end for bu_name...
        # end if load_business_units

        # WE DON'T WANT TO DO THIS HERE ANY MORE!
        # This is now done in the bulk document processing
        # using conditions_delete and conditions_create
        # asset_list = [
        #     item
        #     for item in asset_list
        #     if not item.get("deleted", False) and not item.get("expired", False)
        # ]

        total_count = len(asset_list)

        number = self._thread_number

        if total_count >= number:
            partition_size = total_count // number
            remainder = total_count % number
        else:
            partition_size = total_count
            number = 1
            remainder = 0

        logger.info(
            "Processing -> %s Media Assets, thread number -> %s, partition size -> %s",
            str(total_count),
            number,
            partition_size,
        )

        threads = []

        start = 0
        for index in range(number):
            extra = 1 if remainder > 0 else 0
            end = start + partition_size + extra
            if remainder > 0:
                remainder -= 1

            thread = threading.Thread(
                name=f"load_assets_{index + 1:02}",
                target=self.thread_wrapper,
                args=(
                    self.load_assets_worker,
                    asset_list,
                    partition_size + extra,
                    start,
                    download_assets,
                ),
            )
            thread.start()
            threads.append(thread)
            start = end

        for thread in threads:
            thread.join()

        return True

    # end method definition

    def load_assets_worker(
        self,
        asset_list: list,
        partition_size: int,
        offset: int = 0,
        download_assets: bool = True,
    ):
        """Worker Method for multi-threading

        Args:
            asset_list (list): List of assets to process
            business_unit (str, optional): Name of business unit. Defaults to "".
        """

        logger.info(
            "Processing Media Assets in range from -> %s to -> %s...",
            offset,
            offset + partition_size,
        )

        worker_asset_list = asset_list[offset : offset + partition_size]

        for asset in worker_asset_list:
            asset_id = asset.get("asset_id")
            asset_name = asset.get("name")
            # Store name as asset_name
            asset["asset_name"] = asset_name
            asset_download_url = asset.get("delivery_service_url")
            asset_deleted = asset.get("deleted", False)
            asset_expired = asset.get("expired", False)
            if asset_deleted or asset_expired:
                logger.info(
                    "Asset -> '%s' is deleted or expired. Skipping...",
                    asset_name,
                )
                continue

            if download_assets and asset.get("content_size", 0) > 0:
                success = self.download_asset(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    download_url=asset_download_url,
                )
                if not success:
                    logger.error(
                        "Failed to download asset -> '%s' (%s) to '%s'",
                        asset_name,
                        asset_id,
                        self._download_dir,
                    )
                else:
                    logger.info(
                        "Successfully downloaded asset -> '%s' (%s) to '%s'",
                        asset_name,
                        asset_id,
                        self._download_dir,
                    )

            ## Add metadata to asset and add to new list
            asset.update(self.get_asset_metadata(asset_id))

        # Now we add the article to the Pandas Data Frame in the Data class:
        with self._data.lock():
            self._data.append(worker_asset_list)

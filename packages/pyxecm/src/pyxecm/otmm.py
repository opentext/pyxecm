"""OTMM Module to interact with the OpenText Media Management API.

The documentation for the used REST APIs can be found here:
    - [https://developer.opentext.com](https://developer.opentext.com/ce/products/media-management)
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import os
import platform
import sys
import threading
import traceback
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime
from importlib.metadata import version
from json import JSONDecodeError

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError, RequestException

from pyxecm.helper import Data

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otmm"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Content-Type": "application/x-www-form-urlencoded",
}
REQUEST_TIMEOUT = 60.0

default_logger = logging.getLogger(MODULE_NAME)


class OTMM:
    """Class OTMM is used to automate data extraction from OTMM."""

    # Only class variables or class-wide constants should be defined here:

    PRODUCT_LOOKUP_DOMAIN = "OTMM.DOMAIN.OTM_PRODUCT"
    PRODUCT_METADATA_TABLE = "OTM.TABLE.PRODUCT_TABLE_FIELD"
    PRODUCT_METADATA_FIELD = "PRODUCT_CHAR_ID"
    PRODUCT_NEW_LOOKUP_DOMAIN = "OTMM.DOMAIN.OTM_PRODUCT_NEW.LU"
    PRODUCT_NEW_METADATA_TABLE = "OTMM.FIELD.PRODUCT_NEW.TAB"
    PRODUCT_NEW_METADATA_FIELD = "OTMM.COLUMN.PRODUCT_NEW.TAB"

    logger: logging.Logger = default_logger

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
        business_unit_inclusions: list | None = None,
        product_exclusions: list | None = None,
        product_inclusions: list | None = None,
        asset_exclusions: list | None = None,
        asset_inclusions: list | None = None,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize for the OTMM object.

        Args:
            base_url (str):
                The base URL for accessing OTMM.
            username (str):
                The name of the user.
            password (str):
                The password of the user.
            client_id (str):
                The client ID for the credentials.
            client_secret (str):
                The client secret for the credentials.
            thread_number (int):
                The number of threads for parallel processing for data loads.
            download_dir (str):
                The filesystem directory to download the OTMM assets to.
            business_unit_exclusions (list | None, optional):
                An optional list of business units to exclude. Defaults to None.
            business_unit_inclusions (list | None, optional):
                An optional list of business units to include. Defaults to None.
            product_exclusions (list | None, optional):
                An optional list of products to exclude. Defaults to None.
            product_inclusions (list | None, optional):
                An optional list of products to include. Defaults to None.
            asset_exclusions (list | None, optional):
                An optional list of asset (IDs) to exclude. Defaults to None.
            asset_inclusions (list | None, optional):
                An optional list of asset (IDs) to include. Defaults to None.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otmm")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        # Initialize otcs_config as an empty dictionary
        otmm_config = {}

        # Store the credentials and parameters in a config dictionary:
        otmm_config["baseUrl"] = base_url
        otmm_config["username"] = username
        otmm_config["password"] = password
        otmm_config["clientId"] = client_id
        otmm_config["clientSecret"] = client_secret

        # Make sure we don't have double-slashes if base_url comes with a trailing slash:
        otmm_config["restUrl"] = urllib.parse.urljoin(base_url, "/otmmapi/v6")
        otmm_config["tokenUrl"] = otmm_config["restUrl"] + "/sessions/oauth2/token"
        otmm_config["domainUrl"] = otmm_config["restUrl"] + "/lookupdomains"
        otmm_config["assetsUrl"] = otmm_config["restUrl"] + "/assets"
        otmm_config["searchUrl"] = otmm_config["restUrl"] + "/search/text"

        self._config = otmm_config

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT})

        self._adapter = HTTPAdapter(
            pool_connections=thread_number,
            pool_maxsize=thread_number,
        )
        self._session.mount("http://", self._adapter)
        self._session.mount("https://", self._adapter)

        self._data = Data(logger=self.logger)

        self._thread_number = thread_number

        self._download_dir = download_dir

        self._business_unit_exclusions = business_unit_exclusions
        self._business_unit_inclusions = business_unit_inclusions
        self._product_exclusions = product_exclusions
        self._product_inclusions = product_inclusions
        self._asset_exclusions = asset_exclusions
        self._asset_inclusions = asset_inclusions

        self._access_token = None

        self._asset_download_locks: dict = {}
        self._asset_download_locks_lock = threading.Lock()

    # end method definition

    def thread_wrapper(self, target: Callable, *args: tuple, **kwargs: dict) -> None:
        """Wrap around threads to catch exceptions during exection.

        Args:
            target (Callable):
                The method (callable) the Thread should run.
            args (tuple):
                The arguments for the method.
            kwargs (dict):
                Keyword arguments for the method.

        """

        try:
            target(*args, **kwargs)
        except Exception:
            thread_name = threading.current_thread().name
            self.logger.error(
                "Thread '%s' failed!",
                thread_name,
            )
            self.logger.error(traceback.format_exc())

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict:
                The configuration dictionary.

        """

        return self._config

    # end method definition

    def get_data(self) -> Data:
        """Get the data frame that holds all processed Media Management assets.

        Returns:
            Data:
                Data frame with all processed assets.

        """

        return self._data

    # end method definition

    def authenticate(self) -> str | None:
        """Authenticate at OTMM.

        Supports authentication with client ID and client secret
        or with basic authentication.

        Returns:
            str | None:
                The access token for OTMM.

        """

        request_url = self.config()["tokenUrl"]
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
                headers=REQUEST_HEADERS,
                data=urllib.parse.urlencode(payload),
            )
            response.raise_for_status()

            self._access_token = response.json().get("token_info").get("oauth_token").get("accessToken")
            self._session.headers.update(
                {"Authorization": f"Bearer {self._access_token}"},
            )

        except requests.exceptions.HTTPError as http_error:
            self.logger.error("HTTP error requesting -> %s; error -> %s", request_url, str(http_error))
            self.logger.debug("HTTP request header -> %s", str(REQUEST_HEADERS))
            return None
        except requests.exceptions.ConnectionError:
            self.logger.error("Connection error requesting -> %s", request_url)
            return None
        except requests.exceptions.Timeout:
            self.logger.error("Timeout error requesting -> %s", request_url)
            return None
        except requests.exceptions.RequestException:
            self.logger.error("Request error requesting -> %s", request_url)
            return None
        except Exception:
            self.logger.error("Unexpected error requesting -> %s", request_url)
            return None

        return self._access_token

    # end method definition

    def get_lookup_domains(self) -> dict | None:
        """Get all OTMM lookup domains.

        Args:
            None

        Returns:
            dict | None:
                All OTMM lookup domains.

        Example:
            {
                'lookup_domains_resource': {
                    'lookup_domains': [
                        {
                            'cacheable': True,
                            'datatype': 'CHAR',
                            'domainId': 'ARTESIA.DOMAIN.MEDIA_ANALYSIS.SOURCE.LANGUAGE',
                            'domainValues': [
                                {
                                    'display_value': 'Hausa (Ghana)',
                                    'expired_value': False,
                                    'field_value': {...}
                                },
                                ...
                            ]
                        },
                        ...
                    ]
                }
            }

        """

        request_url = self.config()["domainUrl"]

        try:
            response = self._session.get(
                request_url,
            )

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_error:
            self.logger.error("HTTP error requesting -> %s; error -> %s", request_url, str(http_error))
            return None
        except requests.exceptions.ConnectionError:
            self.logger.error("Connection error requesting -> %s", request_url)
            return None
        except requests.exceptions.Timeout:
            self.logger.error("Timeout error requesting -> %s", request_url)
            return None
        except requests.exceptions.RequestException:
            self.logger.error("Request error requesting -> %s", request_url)
            return None
        except Exception:
            self.logger.error("Unexpected error requesting -> %s", request_url)
            return None

        return response.json()

    # end method definition

    def get_lookup_domain(self, domain: str) -> dict | None:
        """Get OTMM lookup domain with a given name.

        Args:
            domain (str):
                The name / identifier of the domain.

        Returns:
            dict | None:
                The response includes data for the given lookup domain
                or None if the request fails.

        Example:
            {
                'lookup_domain_resource': {
                    'lookup_domain': {
                        'cacheable': True,
                        'datatype': 'CHAR',
                        'domainId': 'OTMM.DOMAIN.OTM_PRODUCT',
                        'domainValues': [
                            {
                                'active_from': '',
                                'active_to': '',
                                'description': 'Active Access',
                                'display_value': 'Active Access',
                                'expired_value': False,
                                'field_value': {
                                    'type': 'string',
                                    'value': '213'
                                }
                            },
                            ...
                        ]
                    }
                }
            }

        """

        request_url = self.config()["domainUrl"] + "/" + domain

        try:
            response = self._session.get(
                request_url,
            )

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_error:
            self.logger.error("HTTP error requesting -> %s; error -> %s", request_url, str(http_error))
            return None
        except requests.exceptions.ConnectionError:
            self.logger.error("Connection error requesting -> %s", request_url)
            return None
        except requests.exceptions.Timeout:
            self.logger.error("Timeout error requesting -> %s", request_url)
            return None
        except requests.exceptions.RequestException:
            self.logger.error("Request error requesting -> %s", request_url)
            return None
        except Exception:
            self.logger.error("Unexpected error requesting -> %s", request_url)
            return None

        return response.json()

    # end method definition

    def get_lookup_domain_values(self, domain: str) -> list | None:
        """Get values of an OTMM lookup domain with a given name.

        Args:
            domain (str):
                The name / identifier of the domain.

        Returns:
            list | None:
                The list of domain values or None if the request fails.

        """

        lookup_domain = self.get_lookup_domain(domain=domain)
        if not lookup_domain:
            self.logger.error(
                "Cannot get lookup domain values for domain -> '%s'",
                domain,
            )
            return None

        values = lookup_domain.get("lookup_domain_resource").get("lookup_domain").get("domainValues")

        return values

    # end method definition

    def get_products(self, domain: str = "OTMM.DOMAIN.OTM_PRODUCT") -> dict:
        """Get a dictionary with product names (keys) and IDs (values).

        Args:
            domain (str, optional):
                The identifier of the Domain. Defaults to "OTMM.DOMAIN.OTM_PRODUCT".

        Returns:
            dict:
                Dictionary of all known products.

        """

        lookup_products = self.get_lookup_domain_values(domain) or []

        # Comprehension to create a dictionary.
        # Keys are the product names, values the product IDs.
        # We remove leading and trailing spaces -
        # OTMM data seems to have this in some places.
        return {
            product.get("display_value").strip(): product.get("field_value").get(
                "value",
            )
            for product in lookup_products
        }

    # end method definition

    def get_business_units(
        self,
        domain: str = "OTMM.DOMAIN.OTM_BUSINESS_UNIT.LU",
    ) -> dict:
        """Get a dictionary with business unit names (keys) and business unit IDs (values).

        Args:
            domain (str, optional):
                The domain. Defaults to "OTMM.DOMAIN.OTM_BUSINESS_UNIT.LU".

        Returns:
            dict:
                Dictionary of all known business units.

        """

        lookup_bus = self.get_lookup_domain_values(domain) or []

        # Comprehension to create a dictionary.
        # Keys are the product names, values the product IDs:
        return {bu.get("display_value").strip(): bu.get("field_value").get("value") for bu in lookup_bus}

    # end method definition

    def get_asset(self, asset_id: str) -> dict | None:
        """Get an asset based on its ID.

        Args:
            asset_id (str):
                The ID of the asset.

        Returns:
            dict | None:
                A dictionary with asset data or None if the asset is not found.

        Example:
            {
                'asset_resource': {
                    'asset': {
                        'access_control_descriptor': {
                            'permissions_map': {...}
                        },
                        'asset_content_info': {
                            'master_content': {...}
                        },
                        'asset_id': 'e064571da79c926ee14b0850734b49edf42d9ba5',
                        'asset_lock_state_last_update_date': '2024-04-16T15:03:48Z',
                        'asset_lock_state_user_id': '153',
                        'asset_state': 'NORMAL',
                        'asset_state_last_update_date': '2024-04-16T15:03:48Z',
                        'asset_state_user_id': '153',
                        'checked_out': False,
                        'content_editable': True,
                        'content_lock_state_last_update_date': '2023-12-11T20:56:26Z',
                        'content_lock_state_user_id': '202',
                        'content_lock_state_user_name': 'ajohnson3',
                        'content_size': 95873,
                        'content_state': 'NORMAL',
                        'content_state_last_update_date': '2023-12-11T20:56:26Z',
                        'content_state_user_id': '202',
                        'content_state_user_name': 'Amanda Johnson',
                        'content_type': 'ACROBAT',
                        'creator_id': '202',
                        'date_imported': '2023-12-11T20:56:26Z',
                        'date_last_updated': '2024-04-16T15:03:48Z',
                        'deleted': False,
                        'delivery_service_url': 'https://assets.opentext.com/adaptivemedia/rendition?id=726d14f14bb1ae93c3efda5a870399a20c991770',
                        'expired': False,
                        'import_job_id': 5776,
                        'import_user_name': 'ajohnson3',
                        'latest_version': True,
                        'legacy_model_id': 104,
                        'locked': False,
                        'master_content_info': {
                            'content_checksum': '2a31defcf7ad2feb7c557acb068a5c22',
                            'content_data': {...},
                            'content_kind': 'MASTER',
                            'content_manager_id': 'ARTESIA.CONTENT.GOOGLE.CLOUD',
                            'content_size': 95873,
                            'height': -1,
                            'id': 'b563035e050a89e58a921df8a4047a0673ad9691',
                            'mime_type': 'application/pdf',
                            'name': 'a-business-case-for-arcsight-soar-wp.pdf',
                            'unit_of_size': 'BYTES',
                            'url': '/otmmapi/v6/renditions/b563035e050a89e58a921df8a4047a0673ad9691',
                            'width': -1
                        },
                        'metadata_lock_state_user_name': 'ababigian',
                        'metadata_model_id': 'OTM.MARKETING.MODEL',
                        'metadata_state_user_name': 'Andra Babigian',
                        'mime_type': 'application/pdf',
                        'name': 'a-business-case-for-arcsight-soar-pp-en.pdf',
                        'original_asset_id': '726d14f14bb1ae93c3efda5a870399a20c991770',
                        'product_associations': False,
                        'rendition_content': {
                            'pdf_preview_content': {
                                'content_checksum': '2a31defcf7ad2feb7c557acb068a5c22',
                                'content_data': {
                                    'data_source': 'NO_CONTENT',
                                    'temp_file': False
                                },
                                'content_kind': 'MASTER',
                                'content_manager_id': 'ARTESIA.CONTENT.GOOGLE.CLOUD',
                                'content_size': 95873,
                                'height': -1,
                                'id': 'b563035e050a89e58a921df8a4047a0673ad9691',
                                'mime_type': 'application/pdf',
                                'name': 'a-business-case-for-arcsight-soar-wp.pdf',
                                'unit_of_size': 'BYTES',
                                'url': '/otmmapi/v6/renditions/b563035e050a89e58a921df8a4047a0673ad9691',
                                'width': -1
                            }
                        },
                        'subscribed_to': False,
                        'version': 3
                    }
                }
            }

        """

        request_url = self.config()["assetsUrl"] + "/" + asset_id

        try:
            response = self._session.get(
                request_url,
                headers=REQUEST_HEADERS,
            )

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_error:
            self.logger.error("HTTP error requesting -> %s; error -> %s", request_url, str(http_error))
            self.logger.debug("HTTP request header -> %s", str(REQUEST_HEADERS))
            return None
        except requests.exceptions.ConnectionError:
            self.logger.error("Connection error requesting -> %s", request_url)
            return None
        except requests.exceptions.Timeout:
            self.logger.error("Timeout error requesting -> %s", request_url)
            return None
        except requests.exceptions.RequestException:
            self.logger.error("Request error requesting -> %s", request_url)
            return None
        except Exception:
            self.logger.error("Unexpected error requesting -> %s", request_url)
            return None

        return response.json()

    # end method definition

    def get_business_unit_assets(
        self,
        bu_id: str,
        offset: int = 0,
        limit: int = 200,
    ) -> list | None:
        """Get all Media Assets for a given Business Unit (ID) that are NOT related to a product.

        Args:
            bu_id (str):
                Identifier of the Business Unit. DON'T USE INT HERE! OTMM delivers
                strings for get_business_units()
            offset (int, optional):
                Result pagination. Starting ID. Defaults to 0.
            limit (int, optional):
                Result pagination. Page length. Defaults to 200.

        Returns:
            dict:
                Search Results

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
            "facet_restriction_list": json.dumps(
                {
                    "facet_restriction_list": {
                        "facet_field_restriction": [
                            {
                                "type": "com.artesia.search.facet.FacetSimpleFieldRestriction",
                                "facet_generation_behavior": "EXCLUDE",
                                "field_id": "PRODUCT_CHAR_ID",
                                "value_list": [None],
                            },
                        ],
                    },
                },
            ),
            "search_condition_list": [
                json.dumps(
                    {
                        "search_condition_list": {
                            "search_condition": [
                                {
                                    "type": "com.artesia.search.SearchTabularCondition",
                                    "metadata_table_id": "OTMM.FIELD.BUSINESS_UNIT.TAB",
                                    "tabular_field_list": [
                                        {
                                            "type": "com.artesia.search.SearchTabularFieldCondition",
                                            "metadata_field_id": "OTMM.COLUMN.BUSINESS_UNIT.TAB",
                                            "relational_operator_id": "ARTESIA.OPERATOR.CHAR.CONTAINS",
                                            "value": str(bu_id),
                                            "left_paren": "(",
                                            "right_paren": ")",
                                        },
                                    ],
                                },
                            ],
                        },
                    },
                ),
            ],
        }

        # Convert list values into comma-separated strings:
        flattened_data = {k: v if not isinstance(v, list) else ",".join(v) for k, v in payload.items()}

        # Use OTMM's search to find the assets for the business unit:
        search_result = self.search_assets(flattened_data)

        if not search_result or "search_result_resource" not in search_result:
            self.logger.error(
                "No assets found via search for business unit with ID -> '%s'!",
                bu_id,
            )
            return None
        search_result = search_result.get("search_result_resource")

        hits = search_result["search_result"]["hit_count"]
        hits_total = search_result["search_result"]["total_hit_count"]

        asset_list = search_result.get("asset_list", None)

        hits_remaining = hits_total - hits

        while hits_remaining > 0:
            flattened_data["after"] += hits
            search_result = self.search_assets(flattened_data)

            if not search_result or "search_result_resource" not in search_result:
                break

            search_result = search_result.get("search_result_resource")

            hits = search_result["search_result"]["hit_count"]
            hits_remaining = hits_remaining - hits

            asset_list += search_result.get("asset_list", [])

        return asset_list

    # end method definition

    def get_product_assets(
        self,
        product_id: str,
        offset: int = 0,
        limit: int = 200,
        metadata_table_id: str = "OTM.TABLE.PRODUCT_TABLE_FIELD",
        metadata_field_id: str = "PRODUCT_CHAR_ID",
    ) -> list | None:
        """Get all Media Assets for a given product (ID).

        This does currently NOT include the asset metadata even though lead type
        is set to "metadata" below as "metadata_to_return" is set to a single field.

        Args:
            product_id (str):
                Identifier of the product. DON'T USE `int` HERE!
                OTMM delivers strings for get_products()
            offset (int, optional):
                Result pagination. Starting ID. Defaults to 0.
            limit (int, optional):
                Result pagination. Page length. Defaults to 200.
            metadata_table_id (str, optional):
                Specific descriptor for the metadata table ID in OTMM.
            metadata_field_id (str, optional):
                Specific descriptor for the metadata field ID in OTMM.

        Returns:
            dict:
                Search Results

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
                json.dumps(
                    {
                        "search_condition_list": {
                            "search_condition": [
                                {
                                    "type": "com.artesia.search.SearchTabularCondition",
                                    "metadata_table_id": str(metadata_table_id),
                                    "tabular_field_list": [
                                        {
                                            "type": "com.artesia.search.SearchTabularFieldCondition",
                                            "metadata_field_id": str(metadata_field_id),
                                            "relational_operator_id": "ARTESIA.OPERATOR.CHAR.CONTAINS",
                                            "value": str(product_id),
                                            "left_paren": "(",
                                            "right_paren": ")",
                                            # "relational_operator": "or"
                                        },
                                    ],
                                },
                            ],
                        },
                    },
                ),
            ],
        }

        # Convert list values into comma-separated strings:
        flattened_data = {k: v if not isinstance(v, list) else ",".join(v) for k, v in payload.items()}

        # Use OTMM's search to find the assets for the product:
        search_result = self.search_assets(payload=flattened_data)

        if not search_result or "search_result_resource" not in search_result:
            self.logger.error("No assets found via search!")
            return None
        search_result = search_result.get("search_result_resource")

        hits = search_result["search_result"]["hit_count"]
        hits_total = search_result["search_result"]["total_hit_count"]

        asset_list = search_result.get("asset_list", None)

        hits_remaining = hits_total - hits

        # Iterate through all result pages:
        while hits_remaining > 0:
            # Calculate offset for next page:
            flattened_data["after"] += hits
            search_result = self.search_assets(payload=flattened_data)

            if not search_result or "search_result_resource" not in search_result:
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
        asset_modification_date: str | None = None,
    ) -> bool:
        """Download a given media asset.

        Args:
            asset_id (str):
                ID of the asset to download. This becomes the file name.
            asset_name (str):
                The name of the asset.
            download_url (str, optiona):
                URL to download the asset (optional).
            asset_modification_date (str | None, optional):
                The last asset modification in OpenText Media Management.

        Returns:
            bool:
                True = success, False = failure

        """

        # Acquire per-asset lock
        with self._asset_download_locks_lock:
            if asset_id not in self._asset_download_locks:
                self._asset_download_locks[asset_id] = threading.Lock()
            asset_lock = self._asset_download_locks[asset_id]

        request_url = download_url if download_url else self.config()["assetsUrl"] + "/" + asset_id + "/contents"

        # We use the Asset ID as the filename to avoid name collisions:
        file_name = os.path.join(self._download_dir, asset_id)

        success = False

        with asset_lock:
            try:
                if os.path.exists(file_name):
                    if asset_modification_date:
                        file_mod_time = datetime.fromtimestamp(os.path.getmtime(file_name), tz=UTC)
                        date_last_updated = datetime.strptime(
                            asset_modification_date,
                            "%Y-%m-%dT%H:%M:%SZ",
                        ).replace(tzinfo=UTC)
                        download_up_to_date: bool = file_mod_time >= date_last_updated
                    else:
                        download_up_to_date = True

                    if download_up_to_date:
                        self.logger.debug(
                            "Asset -> '%s' (%s) has been downloaded before and is up to date. Skipping download to -> %s...",
                            asset_name,
                            asset_id,
                            file_name,
                        )
                        success = True
                    else:
                        self.logger.debug(
                            "Asset -> '%s' (%s) has been downloaded before, but it is outdated. Updating download to -> %s...",
                            asset_name,
                            asset_id,
                            file_name,
                        )
                        os.remove(file_name)

                # We only download if we have no success yet.
                # Success means the file is already there and we don't
                # need to update it.
                if not success:
                    if not os.path.exists(self._download_dir):
                        # Create the directory
                        os.makedirs(self._download_dir)

                    self.logger.info(
                        "Downloading asset -> '%s' (%s) to -> %s...",
                        asset_name,
                        asset_id,
                        file_name,
                    )
                    response = self._session.get(request_url, stream=True)
                    response.raise_for_status()
                    with open(file_name, "wb") as f:
                        f.writelines(response.iter_content(chunk_size=8192))
                    success = True
            # end try:

            except HTTPError as http_error:
                self.logger.error("HTTP error requesting -> %s; error -> %s", request_url, str(http_error))
            except RequestException:
                self.logger.error("Request error requesting -> %s!", request_url)
            except OSError as os_error:
                self.logger.error(
                    "File system error while writing to file -> '%s'; error -> %s", file_name, str(os_error)
                )
            except Exception:
                self.logger.error("Unexpected error requesting -> %s!", request_url)
        # end with asset_lock:

        # Cleanup: Remove the lock for this asset if it's not currently in use by any thread.
        with self._asset_download_locks_lock:
            # Check if a lock exists for this asset_id. It is IMPORTANT to reassign the variable here!
            asset_lock = self._asset_download_locks.get(asset_id)
            if asset_lock and asset_lock.acquire(blocking=False):
                # Try to acquire the lock immediately without waiting.
                # If this succeeds, it means no thread currently holds or is waiting for this lock.
                try:
                    # Safe to delete the lock now because no one else is using it
                    del self._asset_download_locks[asset_id]
                finally:
                    # Release the lock we just acquired to leave system state consistent
                    asset_lock.release()
            # If acquire() failed, some other thread is still using or waiting for the lock,
            # so do not delete it yet.
        # end self._asset_download_locks_lock:

        return success

    # end method definition

    def remove_stale_download(
        self,
        asset_id: str,
        asset_name: str = "",
    ) -> bool:
        """Remove stale download file for an expired or deleted asset.

        Args:
            asset_id (str):
                The ID of the asset to delete in the file system.
            asset_name (str, optional):
                The name of the assets. Just uswed for logging.

        Returns:
            bool: True = success, False = failure

        """

        file_name = os.path.join(self._download_dir, asset_id)

        try:
            if os.path.exists(file_name):
                self.logger.debug(
                    "Deleting stale download file -> '%s' for asset %s...",
                    file_name,
                    "-> '{}' ({})".format(asset_name, asset_id) if asset_name else "-> {}".format(asset_id),
                )
                os.remove(file_name)
                return True
        except OSError as os_error:
            self.logger.error("File system error while deleting file -> '%s'; error -> %s", file_name, str(os_error))

        return False

    # end method definition

    def search_assets(self, payload: dict) -> dict | None:
        """Search an asset based on the given parameters / criterias.

        Args:
            payload (dict):
                In the format of:
                payload = {
                    "PRODUCT_CHAR_ID": "Extended ECM for Engineering",
                    "BUSINESS_AREA_CHAR_ID": "Content",
                    "keyword_query": "*",
                    "limit": "5",
                }

        Returns:
            dict | None:
                The search results.

        Example:
            {
                'search_result_resource': {
                    'search_result': {
                        'asset_group_count': {
                            'entry': [...]
                        },
                        'asset_id_list': [
                            '00084f808d1331bca1f24134bde9cd8e742fe24a',
                            '000af201d7130d1bb2778af672f3bfb554ea965a',
                            '000f9594985b766ee495c27172446d5c9c4e0ebf',
                            '0012d344dc39d4d23aaeb04fbe9db3b21daee6e0',
                            '00135d36232d66b6f11e0020f317244d08a613d1'
                        ],
                        'contains_invalid_conditions': False,
                        'facet_field_response_list': [
                            {...},
                            {...},
                            ...
                        ],
                        'hit_count': 5,
                        'offset': 0,
                        'total_hit_count': 11886
                    },
                    'asset_list': [
                        {
                            'access_control_descriptor': {...},
                            'asset_content_info': {...},
                            'asset_id': '00084f808d1331bca1f24134bde9cd8e742fe24a',
                            'asset_lock_state_last_update_date': '2024-01-03T16:47:22Z',
                            'asset_lock_state_user_id': '166',
                            'asset_state': 'NORMAL',
                            'asset_state_last_update_date': '2024-01-03T16:47:22Z',
                            'asset_state_user_id': '166',
                            'checked_out': False,
                            'content_editable': True,
                            'content_lock_state_last_update_date': '2021-11-22T16:32:59Z',
                            'content_lock_state_user_id': '49',
                            'content_lock_state_user_name': 'sspasik',
                            'content_size': 3103,
                            'content_state': 'NORMAL',
                            'content_state_last_update_date': '2021-11-22T16:32:57Z',
                            'content_state_user_id': '49',
                            'content_state_user_name': 'Srgjan Spasik',
                            'content_type': 'BITMAP',
                            ...
                        },
                        ...
                    ]
                }
            }

        """

        request_url = self.config()["searchUrl"]

        encoded_payload = urllib.parse.urlencode(payload, safe="/:")

        try:
            response = self._session.post(
                request_url,
                headers=REQUEST_HEADERS,
                data=encoded_payload,
            )

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_error:
            self.logger.error("HTTP error requesting -> %s; error -> %s", request_url, str(http_error))
            self.logger.debug("HTTP request header -> %s", str(REQUEST_HEADERS))
            return None
        except requests.exceptions.ConnectionError:
            self.logger.error("Connection error requesting -> %s", request_url)
            return None
        except requests.exceptions.Timeout:
            self.logger.error("Timeout error requesting -> %s", request_url)
            return None
        except requests.exceptions.RequestException:
            self.logger.error("Request error requesting -> %s", request_url)
            return None
        except Exception:
            self.logger.error("Unexpected error requesting -> %s", request_url)
            return None

        return response.json()

    # end method definition

    def get_asset_details(
        self,
        asset_id: str,
        level_of_detail: str = "slim",
        load_multilingual_field_values: bool = True,
        load_subscribed_to: bool = True,
        load_asset_content_info: bool = True,
        load_metadata: bool = True,
        load_inherited_metadata: bool = True,
        load_thumbnail_info: bool = True,
        load_preview_info: bool = True,
        load_pdf_preview_info: bool = True,
        load_3d_preview_info: bool = True,
        load_destination_links: bool = True,
        load_security_policies: bool = True,
        load_path: bool = True,
        load_deep_zoom_info: bool = True,
    ) -> dict | None:
        """Retrieve details of an asset based on the given parameters / criterias.

        Args:
            asset_id (str):
                The ID of the asset to query.
            level_of_detail (str, optional):
                Can either be "slim" or "full". "slim" is the default.
            load_multilingual_field_values (bool, optional):
                If True, load multilingual fields, default = True.
            load_subscribed_to (bool, optional):
                If True, load subscriber information, default = True.
            load_asset_content_info (bool, optional):
                If True, load content information, default = True.
            load_metadata (bool, optional):
                If True, load metadata, default = True.
            load_inherited_metadata (bool, optional):
                If True, load inherited metadata, default = True.
            load_thumbnail_info (bool, optional):
                If True, load thumbnail information, default = True.
            load_preview_info (bool, optional):
                If True, load preview information, default = True.
            load_pdf_preview_info (bool, optional):
                If true, load PDF preview information, default = True.
            load_3d_preview_info (bool, optional):
                If True, load 3D preview information, default = True.
            load_destination_links (bool, optional):
                If true, load destination links, default = True.
            load_security_policies (bool, optional):
                If True, load security policies, default = True.
            load_path (bool, optional):
                If True, load path, default = True.
            load_deep_zoom_info(bool, optional):
                If True, load deep zoom information, default = True.

        Returns:
            dict | None:
                Metadata information as dict with values as list

        Example:
            {
                'asset_resource': {
                    'asset': {
                        'access_control_descriptor': {
                            'permissions_map': {...}
                        },
                        'asset_content_info': {
                            'master_content': {...}
                        },
                        'asset_id': 'e064571da79c926ee14b0850734b49edf42d9ba5',
                        'asset_lock_state_last_update_date': '2024-04-16T15:03:48Z',
                        'asset_lock_state_user_id': '153',
                        'asset_state': 'NORMAL',
                        'asset_state_last_update_date': '2024-04-16T15:03:48Z',
                        'asset_state_user_id': '153',
                        'checked_out': False,
                        'content_editable': True,
                        'content_lock_state_last_update_date': '2023-12-11T20:56:26Z',
                        'content_lock_state_user_id': '202',
                        'content_lock_state_user_name': 'ajohnson3',
                        'content_size': 95873,
                        'content_state': 'NORMAL',
                        'content_state_last_update_date': '2023-12-11T20:56:26Z',
                        'content_state_user_id': '202',
                        'content_state_user_name': 'Amanda Johnson',
                        'content_type': 'ACROBAT',
                        'creator_id': '202',
                        'date_imported': '2023-12-11T20:56:26Z',
                        'date_last_updated': '2024-04-16T15:03:48Z',
                        'deleted': False,
                        'delivery_service_url': 'https://assets.opentext.com/adaptivemedia/rendition?id=726d14f14bb1ae93c3efda5a870399a20c991770',
                        'expired': False,
                        'import_job_id': 5776,
                        'import_user_name': 'ajohnson3',
                        'latest_version': True,
                        'legacy_model_id': 104,
                        'links': {
                            'links': [...],
                            'source_id': 'e064571da79c926ee14b0850734b49edf42d9ba5'
                        },
                        'locked': False,
                        'master_content_info': {
                            'content_checksum': '2a31defcf7ad2feb7c557acb068a5c22',
                            'content_data': {...},
                            'content_kind': 'MASTER',
                            'content_manager_id': 'ARTESIA.CONTENT.GOOGLE.CLOUD',
                            'content_size': 95873,
                            'height': -1,
                            'id': 'b563035e050a89e58a921df8a4047a0673ad9691',
                            'mime_type': 'application/pdf',
                            'name': 'a-business-case-for-arcsight-soar-wp.pdf',
                            'unit_of_size': 'BYTES',
                            'url': '/otmmapi/v6/renditions/b563035e050a89e58a921df8a4047a0673ad9691',
                            'width': -1
                        },
                        'metadata': {
                            'type': 'com.artesia.metadata.MetadataModel',
                            'id': 'OTM.MARKETING.MODEL',
                            'name': 'OTM Marketing Tags',
                            'metadata_element_list': [...],
                            'has_multilingual_fields': False,
                            'legacy_id': 104
                        },
                        'metadata_lock_state_user_name': 'ababigian',
                        'metadata_model_id': 'OTM.MARKETING.MODEL',
                        'metadata_state_user_name': 'Andra Babigian',
                        'mime_type': 'application/pdf',
                        'name': 'a-business-case-for-arcsight-soar-pp-en.pdf',
                        'original_asset_id': '726d14f14bb1ae93c3efda5a870399a20c991770',
                        'path_list': [
                            {...}
                        ],
                        'product_associations': False,
                        'rendition_content': {
                            'pdf_preview_content': {...}
                        },
                        'security_policy_list': [
                            {...}
                        ],
                        'subscribed_to': False,
                        'version': 3
                    }
                }
            }

        """

        request_url = self.config()["assetsUrl"] + "/" + asset_id

        params = {
            "load_type": "custom",
            "level_of_detail": level_of_detail,
            "data_load_request": json.dumps(
                {
                    "data_load_request": {
                        "load_multilingual_field_values": load_multilingual_field_values,
                        "load_subscribed_to": load_subscribed_to,
                        "load_asset_content_info": load_asset_content_info,
                        "load_metadata": load_metadata,
                        "load_inherited_metadata": load_inherited_metadata,
                        "load_thumbnail_info": load_thumbnail_info,
                        "load_preview_info": load_preview_info,
                        "load_pdf_preview_info": load_pdf_preview_info,
                        "load_3d_preview_info": load_3d_preview_info,
                        "load_destination_links": load_destination_links,
                        "load_security_policies": load_security_policies,
                        "load_path": load_path,
                        "load_deep_zoom_info": load_deep_zoom_info,
                    },
                },
            ),
        }

        try:
            response = self._session.get(
                request_url,
                headers=REQUEST_HEADERS,
                params=params,
            )

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_error:
            self.logger.error("HTTP error requesting -> %s; error -> %s", request_url, str(http_error))
            self.logger.debug("HTTP request header -> %s", str(REQUEST_HEADERS))
            return None
        except requests.exceptions.ConnectionError:
            self.logger.error("Connection error requesting -> %s", request_url)
            return None
        except requests.exceptions.Timeout:
            self.logger.error("Timeout error requesting -> %s", request_url)
            return None
        except requests.exceptions.RequestException:
            self.logger.error("Request error requesting -> %s", request_url)
            return None
        except Exception:
            self.logger.error("Unexpected error requesting -> %s", request_url)
            return None

        return response.json()

    # end method definition

    def prepare_asset_data(self, asset_id: str, asset: dict | None = None) -> dict:
        """Prepare the asset data for the Pandas Data frame.

        The asset data is either provided with the asset parameter or
        retrieved by the method.

        Args:
            asset_id (str):
                The ID of the asset.
            asset (dict | None, optional):
                If the asset data structure is already available pass it
                with this parameter. Make sure the asset data was retrieved
                to include the metadata. If None is provided then the method
                will retrieve the asset data (including metadata) on the fly.

        Returns:
            dict | None:
                The simplified / flat structure for the Pandas data frame.

        Example:
            {
                'OTMM_CUSTOM_FIELD_TITLE': 'A Business Case for ArcSight SOAR',
                'OTMM_CUSTOM_FIELD_DESCRIPTION': 'Cybersecurity is a complex problem.',
                'OTMM_CUSTOM_FIELD_KEYWORDS': 'SOAR, SIEM, cybersecurity, SecOps, SOC, cybersecurity automation',
                'CONTENT_TYPE_COMBO_CHAR_ID': None,
                'OTMM_FIELD_IMAGE_TYPE': None,
                'OTM_TABLE_APPROVED_USAGE_FIELD': None,
                'OTMM_FIELD_RESOURCE_LIBRARY_TAB': ['Resource Library'],
                'LANGUAGE_COMBO_CHAR_ID': 'English',
                'OTMM_CUSTOM_FIELD_PART_NUMBER': '762-000033-003',
                'OTMM_FIELD_AVIATOR': None,
                'OTMM_FIELD_BUSINESS_UNIT_TAB': ['Cybersecurity'],
                'OTM_TABLE_PRODUCT_TABLE_FIELD': ['ArcSight Enterprise Security Manager', 'Arcsight Intelligence'],
                'OTMM_FIELD_PRODUCT_NEW_TAB': [],
                'OTMM_FIELD_MARKET_SEGMENT_TAB': [],
                'OTM_TABLE_INDUSTRY_TABLE_FIELD': [],
                'OTMM_CUSTOM_FIELD_URL': None,
                'OTMM_CUSTOM_FIELD_PREVIOUS_URL': 'https://www.microfocus.com/media/white-paper/a-business-case-for-arcsight-soar-wp.pdf',
                'OTMM_CUSTOM_FIELD_CONTENT_OWNER': 'Steve Jones',
                'OTMM_CUSTOM_FIELD_EMAIL': 'sjones2@opentext.com',
                'OTMM_CUSTOM_FIELD_JOB_NUMBER': [],
                'OTM_TABLE_BUSINESS_AREA_TABLE_FIELD': [],
                'OTM_TABLE_JOURNEY_TABLE_FIELD': [],
                'OTMM_FIELD_PERSONA_TAB': [],
                'OTMM_FIELD_SERVICES_TAB': [],
                'OTMM_FIELD_REGION_TAB': [],
                'OTMM_FIELD_PURPOSE_TAB': ['Marketing'],
                'AODA_CHAR_ID': 'Yes',
                'REVIEW_CADENCE_CHAR_ID': 'Quarterly',
                'CONTENT_CREATED_DATE_ID': '2023-10-18T07:00:00Z',
                'ARTESIA_FIELD_EXPIRATIONDATE': None,
                'OTMM_CUSTOM_FIELD_REAL_COMMENTS': None
            }

        """

        # If the asset dictionary is not already provided
        # we retrieve it here:
        if not asset:
            asset = self.get_asset_details(asset_id=asset_id)
            if asset is None:
                self.logger.error(
                    "Cannot get asset details for asset with ID -> %s",
                    asset_id,
                )
                return {}

        # We drill down to the actual asset data:
        if "asset_resource" in asset:
            asset = asset["asset_resource"]
        if "asset" in asset:
            asset = asset["asset"]

        if "metadata" not in asset:
            self.logger.error(
                "The provided data for asset with ID -> '%s' was retrieved without metadata - cannot prepare metadata fields.",
                asset_id,
            )
            return {}

        # Read Metadata from nested structure
        try:
            """
            metadata is a list of dictionaries. Each item has these keys:
            * type (str)
            * id (str)
            * name (str)
            * value (dict)
              - cascading_domain_value (bool)
              - domain_value (bool)
              - is_locked (bool)
              - value (dict)
                  + type (str)
                  + value (str)
            * metadata_element_list (list)
            * display_value
            """
            metadata_list = (
                asset.get("metadata", {}).get("metadata_element_list", [])[0].get("metadata_element_list", [])
            )
        except JSONDecodeError:
            self.logger.error(
                "Cannot decode JSON response for asset with ID -> %s",
                asset_id,
            )
            return {}
        except IndexError:
            self.logger.error(
                "Cannot find metadata in asset with ID -> %s",
                asset_id,
            )
            return {}

        # Initialize empty result dict
        result = {}

        # Extract Metadata fields with values as list and build up
        # a dictionary:
        for metadata in metadata_list:
            # IDs may have dots and spaces that we don't want as dictionary keys.
            # We remove spaces and replace dots with underscores
            # (example: OTMM.CUSTOM.FIELD_ PART_NUMBER -> OTMM_CUSTOM_FIELD_PART_NUMBER):
            dict_key = metadata.get("id").replace(" ", "").replace(".", "_")

            # OTMM has a variety of metadata field types.
            # This includes list values, drop-down lists and strings.
            # Each of these have a different representation in
            # the 'metadata' structure:
            if "value" in metadata and "value" in metadata["value"]:  # do we have a scalar value (plain string)?
                value_dict = metadata.get("value").get("value")
                if "value" in value_dict:
                    result[dict_key] = value_dict.get("value")
                elif "display_value" in value_dict:  # is to a domain value?
                    result[dict_key] = value_dict.get("display_value")
                else:
                    result[dict_key] = None
            elif "metadata_element_list" in metadata:  # do we have a list value?
                # Create list with a comprehension:
                value_list = [
                    value.get("value").get("display_value")
                    for element in metadata.get("metadata_element_list", [])  # outer loop
                    for value in element.get("values", [])  # inner loop
                ]
                result[dict_key] = value_list
            else:  # it may also be that there's no value:
                self.logger.debug(
                    "No value field in metadata -> %s for key -> '%s'",
                    str(metadata),
                    dict_key,
                )
                result[dict_key] = None

        self.logger.debug(
            "Retrieved asset details for asset with ID -> %s: %s",
            asset_id,
            str(result),
        )

        return result

    # end method definition

    def load_assets(
        self,
        load_products: bool = True,
        load_business_units: bool = True,
        download_assets: bool = True,
    ) -> bool:
        """Load all Media Assets for Products and Business Units into a Pandas data frame.

        Args:
            load_products (bool, optional):
                If True, load assets on Business Unit level.
                Defaults to True.
            load_business_units (bool, optional):
                If True, load assets on Product level. Defaults to True.
            download_assets (bool, optional):
                Only if True assets will be downloaded. Defaults to True.

        Returns:
            bool: True = Success, False = Failure

        Example:
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
                'content_path': 'data/repository/original/generative-ai-governance-essentials-wp-en_56cbbfe.pdf',
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
            #
            # Collect assets for old (non-rebranded) products:
            #
            products = self.get_products(domain=OTMM.PRODUCT_LOOKUP_DOMAIN)  # dictionary with key = name and value = ID

            if self._product_inclusions is not None:
                products_filtered = {}
                self.logger.info(
                    "Apply include filter on products -> %s",
                    str(self._product_inclusions),
                )
                for key in self._product_inclusions:
                    if key in products:
                        products_filtered[key] = products[key]

                products = products_filtered

            if self._product_exclusions:
                self.logger.info(
                    "Excluding products -> %s",
                    str(self._product_exclusions),
                )
                for key in self._product_exclusions:
                    # pop(key, None) will remove the key if it exists,
                    # and do nothing if it doesn't:
                    products.pop(key, None)

            for product_name, product_id in products.items():
                if "DO NOT USE" in product_name:
                    continue

                self.logger.info(
                    "Processing assets for product -> '%s'...",
                    product_name,
                )

                assets = self.get_product_assets(
                    product_id=product_id,
                    metadata_table_id=OTMM.PRODUCT_METADATA_TABLE,
                    metadata_field_id=OTMM.PRODUCT_METADATA_FIELD,
                )

                if not assets:
                    self.logger.info(
                        "Found no assets for product -> '%s'. Skipping it...",
                        product_name,
                    )
                    continue

                # We enrich the dictionary with tags for workspace type and
                # workspace name for later bulk processing:
                for asset in assets:
                    asset["workspace_type"] = "Product"
                    asset["workspace_name"] = product_name

                # Filter out assets that are not files - we use the content size
                # attribute for this:
                asset_list += [asset for asset in assets if "content_size" in asset]

            #
            # Collect assets for new (rebranded) products:
            #
            products = self.get_products(
                domain=OTMM.PRODUCT_NEW_LOOKUP_DOMAIN
            )  # dictionary with key = name and value = ID

            if self._product_inclusions is not None:
                products_filtered = {}
                self.logger.info(
                    "Apply include filter on products -> %s",
                    str(self._product_inclusions),
                )
                for key in self._product_inclusions:
                    if key in products:
                        products_filtered[key] = products[key]

                products = products_filtered

            if self._product_exclusions:
                self.logger.info(
                    "Excluding products -> %s",
                    str(self._product_exclusions),
                )
                for key in self._product_exclusions:
                    # pop(key, None) will remove the key if it exists,
                    # and do nothing if it doesn't:
                    products.pop(key, None)

            for product_name, product_id in products.items():
                if "DO NOT USE" in product_name:
                    continue

                self.logger.info(
                    "Processing assets for product (rebranded) -> '%s'...",
                    product_name,
                )

                assets = self.get_product_assets(
                    product_id=product_id,
                    metadata_table_id=OTMM.PRODUCT_NEW_METADATA_TABLE,
                    metadata_field_id=OTMM.PRODUCT_NEW_METADATA_FIELD,
                )

                if not assets:
                    self.logger.info(
                        "Found no assets for product (rebranded) -> '%s'. Skipping it...",
                        product_name,
                    )
                    continue

                # We enrich the dictionary with tags for workspace type and
                # workspace name for later bulk processing:
                for asset in assets:
                    asset["workspace_type"] = "Product"
                    asset["workspace_name"] = product_name

                # Filter out assets that are not files - we use the content size
                # attribute for this:
                asset_list += [asset for asset in assets if "content_size" in asset]

        if load_business_units:
            business_units = self.get_business_units()

            if self._business_unit_inclusions is not None:
                business_units_filtered = {}
                self.logger.info(
                    "Apply include filter on business units -> %s",
                    str(self._business_unit_inclusions),
                )
                for key in self._business_unit_inclusions:
                    if key in business_units:
                        business_units_filtered[key] = business_units[key]

                business_units = business_units_filtered

            if self._business_unit_exclusions:
                self.logger.info(
                    "Excluding business units -> %s",
                    str(self._business_unit_exclusions),
                )
                for key in self._business_unit_exclusions:
                    # pop(key, None) will remove the key if it exists,
                    # and do nothing if it doesn't:
                    business_units.pop(key, None)

            for bu_name, bu_id in business_units.items():
                self.logger.info("Processing assets for business unit -> '%s'", bu_name)
                assets = self.get_business_unit_assets(bu_id)

                if not assets:
                    self.logger.info(
                        "Found no assets for business unit -> '%s'. Skipping it...",
                        bu_name,
                    )
                    continue

                # We enrich the dictionary with tags for workspace type and name for
                # later bulk processing:
                for asset in assets:
                    asset["workspace_type"] = "Business Unit"
                    asset["workspace_name"] = bu_name

                # Filter out assets that are not files - we use the content size
                # attribute for this:
                asset_list += [asset for asset in assets if "content_size" in asset]

            # end for bu_name...
        # end if load_business_units

        total_count = len(asset_list)

        number = self._thread_number

        if total_count >= number:
            partition_size = total_count // number
            remainder = total_count % number
        else:
            partition_size = total_count
            number = 1
            remainder = 0

        self.logger.info(
            "Processing -> %s media assets, thread number -> %s, partition size -> %s",
            str(total_count),
            str(number),
            str(partition_size),
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
    ) -> None:
        """Worker Method for multi-threading.

        Args:
            asset_list (list):
                Complete list of assets. The thread uses offset an partition size
                to pick its working subset of it.
            partition_size (int):
                The size of the partition.
            offset (int, optional):
                The starting offset for the worker. The default is 0.
            download_assets (bool, optional):
                Whether the thread should download the assets. Default is True.

        Example asset that get's added to the Data Frame:
            {
                'access_control_descriptor': {
                    'permissions_map': {...}
                },
                'asset_content_info': {'master_content': {...}},
                'asset_id': '3eefc89705f53f0540d409cf866f1bc8119f65c0',
                'asset_lock_state_last_update_date': '2024-06-26T22:15:00Z',
                'asset_lock_state_user_id': '153',
                'asset_state': 'NORMAL',
                'asset_state_last_update_date': '2024-06-26T22:15:00Z',
                'asset_state_user_id': '153',
                'checked_out': False,
                'content_editable': True,
                'content_lock_state_last_update_date': '2021-11-22T05:33:46Z',
                'content_lock_state_user_id': '76',
                'content_lock_state_user_name': 'dgoyal',
                'content_size': 25986,
                'content_state': 'NORMAL',
                'content_state_last_update_date': '2021-11-22T05:33:45Z',
                'content_state_user_id': '76',
                'content_state_user_name': 'Dignesh Goyal',
                'content_type': 'BITMAP',
                'creator_id': '76',
                'date_imported': '2021-11-22T05:33:44Z',
                'date_last_updated': '2024-06-26T22:15:00Z',
                'deleted': False,
                'delivery_service_url': 'https://assets.opentext.com/adaptivemedia/rendition?id=3eefc89705f53f0540d409cf866f1bc8119f65c0',
                'expired': False,
                'import_job_id': 381,
                'import_user_name': 'dgoyal',
                'latest_version': True,
                'legacy_model_id': 104,
                'locked': False,
                'master_content_info': {
                    'content_checksum': '2cf0db34b37b2af71c516259c6b8287e',
                    'content_data': {...},
                    'content_kind': 'MASTER',
                    'content_manager_id': 'ARTESIA.CONTENT.GOOGLE.CLOUD',
                    'content_path': 'data/repository/original/co-op-food-logo-ss (1)_21d529dea732.jpg',
                    'content_size': 25986,
                    'height': 192,
                    'id': '21d529dea7324e54b2c00df8573951fcb3f4ebb2',
                    'mime_type': 'image/jpeg',
                    'name': 'co-op-food-logo-ss (1).jpg',
                    'unit_of_size': 'BYTES',
                    'url': '/otmmapi/v6/renditions/21d529dea7324e54b2c00df8573951fcb3f4ebb2',
                    'width': 192
                },
                'metadata_lock_state_user_name': 'ababigian',
                'metadata_model_id': 'OTM.MARKETING.MODEL',
                'metadata_state_user_name': 'Andra Babigian',
                'mime_type': 'image/jpeg',
                'name': 'co-op-food-logo-ss (1).jpg',
                'original_asset_id': '3eefc89705f53f0540d409cf866f1bc8119f65c0',
                'product_associations': False,
                'rendition_content': {
                    'thumbnail_content': {...},
                    'preview_content': {...}
                },
                'subscribed_to': False,
                'thumbnail_content_id': '94d71e6ac14890e89931f2bbfc2da74ffab8db5f',
                'version': 1,
                'workspace_type': 'Product',
                'workspace_name': 'Trading Grid',
                'asset_name': 'co-op-food-logo-ss (1).jpg',
                'OTMM_CUSTOM_FIELD_TITLE': None,
                'OTMM_CUSTOM_FIELD_DESCRIPTION': None,
                'OTMM_CUSTOM_FIELD_KEYWORDS': None,
                'CONTENT_TYPE_COMBO_CHAR_ID': 'Image',
                'OTMM_FIELD_IMAGE_TYPE': None,
                'OTM_TABLE_APPROVED_USAGE_FIELD': 'Internal',
                'OTMM_FIELD_RESOURCE_LIBRARY_TAB': [],
                'LANGUAGE_COMBO_CHAR_ID': 'English',
                'OTMM_CUSTOM_FIELD_PART_NUMBER': None,
                'OTMM_FIELD_AVIATOR': None,
                'OTMM_FIELD_BUSINESS_UNIT_TAB': ['Business Network'],
                'OTM_TABLE_PRODUCT_TABLE_FIELD': ['Trading Grid'],
                'OTMM_FIELD_PRODUCT_NEW_TAB': ['Trading Grid'],
                'OTMM_FIELD_MARKET_SEGMENT_TAB': [],
                'OTM_TABLE_INDUSTRY_TABLE_FIELD': ['Retail'],
                'OTMM_CUSTOM_FIELD_URL': None,
                ...,
                'OTM_TABLE_JOURNEY_TABLE_FIELD': ['Buy', 'Try', 'Learn'],
                ...,
                'REVIEW_CADENCE_CHAR_ID': 'Quarterly',
                'CONTENT_CREATED_DATE_ID': '2021-11-08T00:00:00Z',
                ...
            }

        """

        self.logger.info(
            "Processing media assets in range from -> %s to -> %s...",
            offset,
            offset + partition_size,
        )

        worker_asset_list = asset_list[offset : offset + partition_size]

        for asset in worker_asset_list:
            asset_id = asset.get("asset_id")
            if self._asset_exclusions and asset_id in self._asset_exclusions:
                self.logger.info(
                    "Asset with ID -> %s is in exclusion list. Skipping it...",
                    asset_id,
                )
                asset["included"] = False
                continue
            if self._asset_inclusions and asset_id not in self._asset_inclusions:
                self.logger.info(
                    "Asset with ID -> %s is not in inclusion list. Skipping it...",
                    asset_id,
                )
                asset["included"] = False
                continue
            if self._asset_exclusions or self._asset_inclusions:
                asset["included"] = True
            asset_name = asset.get("name")
            # Store name as asset_name
            asset["asset_name"] = asset_name
            # We cannot fully trust the deliver_service_url -
            # instead we construct a URL that should always work:
            asset_download_url = self.config()["assetsUrl"] + "/" + asset_id + "/contents"
            # We also store the correct download URL to make it available
            # for the data frame and in bulkDocuments:
            asset["download_url"] = asset_download_url
            asset_deleted = asset.get("deleted", False)
            asset_expired = asset.get("expired", False)

            # We can skip the _download_ of deleted or expired assets,
            # but we still want to have them in the Data Frame for
            # bulk processing (to remove them from OTCS)
            if download_assets and asset.get("content_size", 0) > 0 and not asset_deleted and not asset_expired:
                success = self.download_asset(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    download_url=asset_download_url,
                    asset_modification_date=asset.get("date_last_updated"),
                )
                if not success:
                    self.logger.error(
                        "Failed to download asset -> '%s' (%s) to '%s'",
                        asset_name,
                        asset_id,
                        self._download_dir,
                    )
                else:
                    self.logger.info(
                        "Successfully downloaded asset -> '%s' (%s) to '%s'",
                        asset_name,
                        asset_id,
                        self._download_dir,
                    )
            elif asset_deleted or asset_expired:
                success = self.remove_stale_download(
                    asset_id=asset_id,
                    asset_name=asset_name,
                )
                if not success:
                    self.logger.info(
                        "No stale download for asset -> '%s' (%s) in directory -> '%s'. Nothing to clean up.",
                        asset_name,
                        asset_id,
                        self._download_dir,
                    )
                else:
                    self.logger.info(
                        "Deleted stale download for asset -> '%s' (%s) in directory -> '%s'",
                        asset_name,
                        asset_id,
                        self._download_dir,
                    )

            # Add additional custom metadata to the asset.
            asset.update(self.prepare_asset_data(asset_id=asset_id))
            # Create a common title field for all assets that either
            # uses the OTMM title custom field or the asset name. We
            # have to do this AFTER calling prepare_asset_data() to
            # have the custom field available:
            asset["asset_title"] = asset.get("OTMM_CUSTOM_FIELD_TITLE") or asset_name
        # end for asset in worker_asset_list:

        # Now we add the assets processed by the worker
        # to the Pandas Data Frame in the Data class:
        with self._data.lock():
            # Check if we have added the temporary key "included"
            # to handle inclusions or exclusions. Then we want to
            # a) remove the excluded items
            # b) remove the "included" key to avoid polluting the
            #    data frame with an additional temp column
            if self._asset_exclusions or self._asset_inclusions:
                self._data.append(
                    [
                        {k: v for k, v in item.items() if k != "included"}
                        for item in worker_asset_list
                        if item.get("included")
                    ],
                )
            else:
                self._data.append(worker_asset_list)

    # end method definition

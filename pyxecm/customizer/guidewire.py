"""Guidewire Module to interact with the Guidewire REST API ("Cloud API").

See: https://www.guidewire.com/de/developers/apis/cloud-apis
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging

import requests

default_logger = logging.getLogger("pyxecm.customizer.guidewire")


class Guidewire:
    """Class Guidewire is used to retrieve and automate stettings and objects in Guidewire."""

    logger: logging.Logger = default_logger
    _config: dict
    _scope = None
    _token = None

    def __init__(
        self,
        base_url: str,
        client_id: str = "",
        client_secret: str = "",
        username: str = "",
        password: str = "",
        scope: str = "",
    ) -> None:
        """Initialize the Guidewire API client.

        Args:
            base_url (str):
                The base URL of the Guidewire Cloud API.
            client_id (str):
                The Client ID for authentication (optional, required for client credential flow).
            client_secret (str):
                The Client Secret for authentication (optional, required for client credential flow).
            username (str):
                The username for authentication (optional, required for password-based authentication).
            password (str):
                The password for authentication (optional, required for password-based authentication).
            scope (str):
                The OAuth2 scope (optional).

        """

        self._scope = scope
        self._token = None

        guidewire_config = {}
        # Store the credentials and parameters in a config dictionary:
        guidewire_config["clientId"] = client_id
        guidewire_config["clientSecret"] = client_secret
        guidewire_config["username"] = username
        guidewire_config["password"] = password
        guidewire_config["baseUrl"] = base_url.rstrip("/")
        guidewire_config["cloudAPIUrl"] = guidewire_config["baseUrl"] + "/api/v1"
        guidewire_config["tokenUrl"] = guidewire_config["cloudAPIUrl"] + "/oauth2/token"

        self._config = guidewire_config

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict:
                The configuration dictionary with all settings.

        """

        return self._config

    # end method definition

    def authenticate(self) -> bool:
        """Authenticate with the Guidewire API using either client credentials or username/password.

        Returns:
            bool:
                True if authentication is successful, False otherwise.

        """

        request_url = self.config()["tokenUrl"]

        if self.config()["clientId"] and self.config()["clientSecret"]:
            auth_data = {
                "grant_type": "client_credentials",
                "client_id": self.config()["clientId"],
                "client_secret": self.config()["clientSecret"],
            }
        elif self.config()["username"] and self.config()["password"]:
            auth_data = {
                "grant_type": "password",
                "username": self.config()["username"],
                "password": self.config()["password"],
                "client_id": self.config()["clientId"],  # Required for some OAuth2 flows
                "client_secret": self.config()["clientSecret"],  # Required for some OAuth2 flows
            }
        else:
            self.logger.error("Authentication requires either client credentials or username/password.")
            return False

        if self._scope:
            auth_data["scope"] = self._scope

        response = requests.post(request_url, data=auth_data)
        if response.status_code == 200:
            self.token = response.json().get("access_token")
            return True

        return False

    # end method definition

    def request_headers(self) -> dict:
        """Generate request headers including authentication token.

        Returns:
            dict:
                A dictionary containing authorization headers.

        """

        if not self._token:
            self.logger.error("Authentication required. Call authenticate() first.")
            return None

        return {
            "Authorization": "Bearer {}".format(self._token),
            "Content-Type": "application/json",
        }

    # end method definition

    def do_request(self, method: str, endpoint: str, data: dict | None = None, params: dict | None = None) -> dict:
        """Send a request to the Guidewire REST API.

        Args:
            method (str):
                The HTTP method to use (GET, POST, PUT, DELETE).
            endpoint (str):
                The API endpoint to call.
            data (dict):
                The request payload (if applicable).
            params (dict):
                The URL parameters (if applicable).

        Returns:
            dict:
                Response as a dictionary.

        """

        request_url = "{}{}".format(self.base_url, endpoint)
        response = requests.request(method, request_url, headers=self._headers(), json=data, params=params)

        return response.json() if response.content else {}

    # end method definition

    def get_accounts(self) -> dict:
        """Retrieve a list of accounts.

        Returns:
            dict: JSON response containing account data.

        """

        return self.do_request("GET", "/accounts")

    # end method definition

    def get_account(self, account_id: str) -> dict:
        """Retrieve details of a specific account.

        Args:
            account_id: The unique identifier of the account.

        Returns:
            dict: JSON response containing account details.

        """

        return self.do_request("GET", "/accounts/{}".format(account_id))

    # end method definition

    def add_account(self, account_data: dict) -> dict:
        """Create a new account.

        Args:
            account_data: Dictionary containing account information.

        Returns:
            dict: JSON response with created account details.

        """

        return self.do_request("POST", "/accounts", data=account_data)

    # end method definition

    def update_account(self, account_id: str, account_data: dict) -> dict:
        """Update an existing account.

        Args:
            account_id: The unique identifier of the account.
            account_data: Dictionary containing updated account information.

        Returns:
            dict: JSON response with updated account details.

        """

        return self.do_request("PUT", "/accounts/{}".format(account_id), data=account_data)

    # end method definition

    def delete_account(self, account_id: str) -> dict:
        """Delete an account.

        Args:
            account_id: The unique identifier of the account to delete.

        Returns:
            dict: JSON response indicating deletion success.

        """

        return self.do_request("DELETE", "/accounts/{}".format(account_id))

    # end method definition

    def get_claims(self) -> dict:
        """Retrieve a list of claims.

        Returns:
            dict: JSON response containing claim data.

        """

        return self.do_request("GET", "/claims")

    # end method definition

    def get_claim(self, claim_id: str) -> dict:
        """Retrieve details of a specific claim.

        Args:
            claim_id: The unique identifier of the claim.

        Returns:
            dict: JSON response containing claim details.

        """

        return self.do_request("GET", "/claims/{}".format(claim_id))

    # end method definition

    def add_claim(self, claim_data: dict) -> dict:
        """Create a new claim.

        Args:
            claim_data (dict):
                Dictionary containing claim information.

        Returns:
            dict:
                JSON response with created claim details.

        """

        return self.do_request("POST", "/claims", data=claim_data)

    # end method definition

    def update_claim(self, claim_id: str, claim_data: dict) -> dict:
        """Update an existing claim.

        Args:
            claim_id:
                The unique identifier of the claim.
            claim_data:
                Dictionary containing updated claim information.

        Returns:
            dict:
                Response with updated claim details.

        """

        return self.do_request("PUT", "/claims/{}".format(claim_id), data=claim_data)

    # end method definition

    def delete_claim(self, claim_id: str) -> dict:
        """Delete a claim.

        Args:
            claim_id (str):
                The unique identifier of the claim to delete.

        Returns:
            dict:
                Response indicating deletion success.

        """

        return self.do_request("DELETE", "/claims/{}".format(claim_id))

    # end method definition

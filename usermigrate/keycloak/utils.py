""" Utility functions for interacting with a Keycloak server. """

__author__ = "William Tucker"
__date__ = "2020-09-09"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import requests
import json

from usermigrate.keycloak.exceptions import KeycloakAuthenticationError, \
    KeycloakCommunicationError, KeycloakConflictError


class KeycloakApi:

    TOKEN_ENDPOINT = \
        "{url}/auth/realms/{realm}/protocol/openid-connect/token"
    API_ENDPOINT = \
        "{url}/auth/admin/realms/{realm}"

    def __init__(self, url, realm, user, password, verify=True):

        self._url = url
        self._realm = realm
        self._user = user
        self._password = password
        self._verify = verify

        api_endpoint = self.API_ENDPOINT.format(url=url, realm=realm)
        self._api_endpoints = {
            "group": f"{api_endpoint}/groups",
            "user": f"{api_endpoint}/users",
        }

    def __enter__(self):

        access_data = self._fetch_access_data()

        self._key = access_data["access_token"]
        self._access_expires_in = access_data["expires_in"]

        return self

    def __exit__(self, *args):

        self._key = None

    def _fetch_access_data(self):
        """ Sets the key for interacting with the Admin API. """

        # Construct Keycloak API token request
        token_request_data = {
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": self._user,
            "password": self._password
        }

        endpoint = self.TOKEN_ENDPOINT.format(url=self._url, realm=self._realm)
        response = requests.post(endpoint, data=token_request_data,
            verify=self._verify)

        if response.ok:

            return json.loads(response.text)

        elif response.status_code == 401:
            raise KeycloakAuthenticationError(
                ("Couldn't authenticate with Keycloak user '{}'. Is your"
                " password correct?").format(self._user),
                endpoint)
        else:
            raise KeycloakCommunicationError((f"Failed to retrieve API token:"
                f" got {response.status_code} response."), endpoint)

    @property
    def access_expires(self):
        return self._access_expires_in

    def check_connection(self):
        if (self._fetch_access_data()):
            return True

    def search(self, endpoint):
        """ Search for data in Keycloak. """

        pass

    def post(self, endpoint_key, data):
        """ Post some data to a Keycloak API endpoint. """

        if endpoint_key not in self._api_endpoints:
            raise ValueError(f"No endpoint for key '{endpoint_key}'")

        endpoint = self._api_endpoints[endpoint_key]
        headers = {
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
        }
        response = requests.post(endpoint, headers=headers, json=data,
            verify=self._verify)

        if response.status_code == 409:
            raise KeycloakConflictError("Data conflict.", endpoint)

        elif not response.ok:
            raise KeycloakCommunicationError(
                f"Got {response.status_code} response.", endpoint)

        return True

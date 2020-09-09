""" Utility functions for interacting with a Keycloak server. """

__author__ = "William Tucker"
__date__ = "2020-09-09"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import requests
import json

from usermigrate.keycloak.exceptions import KeycloakAuthenticationError, \
    KeycloakCommunicationError, KeycloakConflictError


def parse_groups(users):
    """ Find a set of groups which users could belong to. """

    groups = set()
    for user in users:
        for group in user["groups"]:
            groups.add(group)

    for group in groups:
        yield { "name": group }


class KeycloakApi:

    TOKEN_ENDPOINT = \
        "{url}/auth/realms/{realm}/protocol/openid-connect/token"
    API_ENDPOINT = \
        "{url}/auth/admin/realms/{realm}"

    def __init__(self, url, realm, user, password):

        self._url = url
        self._realm = realm
        self._user = user
        self._password = password

        api_endpoint = self.API_ENDPOINT.format(url=url, realm=realm)
        self._groups_endpoint = f"{api_endpoint}/groups"
        self._users_endpoint = f"{api_endpoint}/users"

    def __enter__(self):

        self._setup_key()
        return self

    def __exit__(self, *args):

        self._key = None

    def _setup_key(self):
        """ Sets the key for interacting with the Admin API. """

        # Construct Keycloak API token request
        token_request_data = {
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": self._user,
            "password": self._password
        }

        endpoint = self.TOKEN_ENDPOINT.format(url=self._url, realm=self._realm)
        response = requests.post(endpoint, data=token_request_data)

        if response.ok:
            self._key = json.loads(response.text)["access_token"]
        elif response.status_code == 401:
            raise KeycloakAuthenticationError(
                ("Couldn't authenticate with Keycloak user '{}'. Is your"
                " password correct?").format(connection_data["username"]),
                endpoint)
        else:
            raise KeycloakCommunicationError((f"Failed to retrieve API token:"
                f" got {response.status_code} response."), endpoint)

    def post(self, endpoint, data):
        """ Post some data to a Keycloak API endpoint. """

        headers = {
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
        }
        response = requests.post(endpoint, headers=headers, json=data)

        if response.status_code == 409:
            raise KeycloakConflictError("Data conflict.", endpoint)

        elif not response.ok:
            raise KeycloakCommunicationError(
                f"Got {response.status_code} response.", endpoint)

        return True

    def post_group(self, data):
        return self.post(self._groups_endpoint, data)

    def post_user(self, data):
        return self.post(self._users_endpoint, data)

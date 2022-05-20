""" Utility functions for interacting with a Keycloak server. """

__author__ = "William Tucker"
__date__ = "2020-09-09"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import requests
import json

from datetime import datetime, timedelta

from usermigrate.keycloak.exceptions import KeycloakAuthenticationError, \
    KeycloakCommunicationError, KeycloakConflictError


class KeycloakApi:

    TOKEN_ENDPOINT = \
        "{url}/auth/realms/master/protocol/openid-connect/token"
    API_ENDPOINT = \
        "{url}/auth/admin/realms/{realm}"

    def __init__(self, url, realm, user, password, verify=True):

        self._url = url
        self._realm = realm
        self._user = user
        self._password = password
        self._verify = verify

        self._reset_token()

        api_endpoint = self.API_ENDPOINT.format(url=url, realm=realm)
        self._api_endpoints = {
            "group": f"{api_endpoint}/groups",
            "user": f"{api_endpoint}/users",
        }

    def __enter__(self):

        self._update_token()
        return self

    def __exit__(self, *args):

        self._reset_token()

    def _reset_token(self):

        self._access_token = None
        self._refresh_token = None
        self._expires = datetime.now()
        self._refresh_expires = datetime.now()

    def _fetch_access_data(self, post_data):
        """ Sets the key for interacting with the Admin API. """

        # Construct Keycloak API token request
        endpoint = self.TOKEN_ENDPOINT.format(url=self._url, realm=self._realm)
        response = requests.post(endpoint, data=post_data,
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

    def _update_token(self, store=True):

        near_time = datetime.now() + timedelta(minutes=1)

        # Skip if token still valid
        if near_time < self._expires:
            return

        request_data = None
        do_refresh = False
        if self._refresh_token and near_time < self._refresh_expires:
            do_refresh = True

        if do_refresh:
            request_data = {
                "client_id": "admin-cli",
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token
            }
        else:
            request_data = {
                "client_id": "admin-cli",
                "grant_type": "password",
                "username": self._user,
                "password": self._password
            }

        access_data = self._fetch_access_data(request_data)

        # Store access token
        self._access_token = access_data["access_token"]
        expires_in = access_data["expires_in"]
        self._expires = datetime.now() + timedelta(seconds=expires_in)

        # Store refresh token
        self._refresh_token = access_data["refresh_token"]
        refresh_expires_in = access_data["refresh_expires_in"]
        self._refresh_expires = datetime.now() + timedelta(
            seconds=refresh_expires_in)

    def check_connection(self):

        self._update_token(store=False)
        return True

    def create_group(self, group_name):
        """ Create a group in Keycloak. """

        self._update_token()

        endpoint = self._api_endpoints["group"]
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        }
        response = requests.post(endpoint, headers=headers, json={"name": group_name},
            verify=self._verify)

        if response.status_code == 409:
            raise KeycloakConflictError("Data conflict.", endpoint)

        elif not response.ok:
            raise KeycloakCommunicationError(
                f"Got {response.status_code} response.", endpoint)

        return True

    def create_user(self, user_data, overwrite=False):
        """ Post some data to a Keycloak API endpoint. """

        self._update_token()

        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        }

        endpoint = self._api_endpoints["user"]
        query = {
            "briefRepresentation": True,
            "exact": True,
            "username": user_data["username"]
        }

        response = requests.get(endpoint, headers=headers, params=query,
            verify=self._verify)

        results = response.json()

        # Create a new user
        if len(results) == 0:

            response = requests.post(endpoint, headers=headers, json=user_data,
                verify=self._verify)

            if response.status_code == 409:
                raise KeycloakConflictError("Data conflict.", endpoint)

            elif not response.ok:
                raise KeycloakCommunicationError(
                    f"Got {response.status_code} response.", endpoint)

            return True

        if not overwrite:
            raise KeycloakConflictError("Data conflict.", endpoint)

        # Update existing user
        user_id = results[0]["id"]
        endpoint = "{0}/{1}".format(endpoint, user_id)

        response = requests.put(endpoint, headers=headers, json=user_data,
            verify=self._verify)

        if not response.ok:
            raise KeycloakCommunicationError(
                f"Got {response.status_code} response.", endpoint)

        return False

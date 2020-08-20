""" User class definition. """

__author__ = "William Tucker"
__date__ = "2020-08-06"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


class KeycloakUser:

    @property
    def permissions(self):
        return self._permissions

    @property
    def data(self):

        return {
            "username": self._username,
            "firstName": self._first_name,
            "lastName": self._last_name,
            "email": self._email,
        }

    def __init__(self, username, first_name, last_name, email, permissions):

        self._username = username
        self._first_name = first_name
        self._last_name = last_name
        self._email = email
        self._permissions = permissions

    def __repr__(self):

        return f"Keycloak User: {self.data}"

""" User class definition. """

__author__ = "William Tucker"
__date__ = "2020-08-06"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


class KeycloakUser:
    """ Abstract class to represent the Keycloak user model. """

    @property
    def groups(self):
        return NotImplementedError()

    @property
    def data(self):
        return NotImplementedError()

    def __repr__(self):

        return f"Keycloak User: {self.data}"

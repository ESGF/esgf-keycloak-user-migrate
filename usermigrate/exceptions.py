""" Exceptions raised by this library. """

__author__ = "William Tucker"
__date__ = "2020-08-19"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


class KeycloakError(Exception):
    """ Generic error related to Keycloak. """

    def __init__(self, message, endpoint):

        self.message = message
        self.endpoint = endpoint
        super().__init__(message)

    def __str__(self):

        return \
            f"Tried Keycloak endpoint: {self.endpoint}\n{self.message}"


class KeycloakCommunicationError(KeycloakError):
    """ Raised on a failed communication with the Keycloak server. """
    pass


class KeycloakAuthenticationError(KeycloakError):
    """ Raised on a 401 response from the Keycloak server. """
    pass


class DatabaseConnectionError(Exception):
    """ Raised when a database connection attempt failed. """
    pass

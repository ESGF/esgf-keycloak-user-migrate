""" Exceptions raised by Keycloak interactions. """

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
            f"Keycloak error for endpoint {self.endpoint}: {self.message}"


class KeycloakCommunicationError(KeycloakError):
    """ Raised on a failed communication with the Keycloak server. """
    pass


class KeycloakAuthenticationError(KeycloakError):
    """ Raised on a 401 response from the Keycloak server. """
    pass


class KeycloakUsernameConflictError(KeycloakError):
    """ Raised on a 409 response from the Keycloak server. """
    pass


class KeycloakConflictError(KeycloakError):
    """ Raised on a 409 response from the Keycloak server. """
    pass

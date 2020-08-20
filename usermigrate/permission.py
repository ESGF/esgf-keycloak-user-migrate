""" Permission class definition. """

__author__ = "William Tucker"
__date__ = "2020-08-06"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


class KeycloakPermission:

    @property
    def group(self):
        return self._group

    @property
    def role(self):
        return self._role

    @property
    def data(self):

        return {
            "name": self._group,
            "role": self._role
        }

    def __init__(self, group, role):

        self._group = group
        self._role = role

    def __repr__(self):

        return f"Keycloak Permission: {self.data}"

""" Script to run the migration. """

__author__ = "William Tucker"
__date__ = "2020-08-04"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import click
import requests
import json
import logging

from requests.exceptions import ConnectionError
from sqlalchemy.exc import ProgrammingError

from usermigrate.db.models import User
from usermigrate.user import KeycloakUser
from usermigrate.db import Connection
from usermigrate.exceptions import KeycloakAuthenticationError, \
    KeycloakCommunicationError, DatabaseConnectionError


LOG = logging.getLogger(__name__)

KEYCLOAK_TOKEN_ENDPOINT = \
    "{url}/auth/realms/{realm}/protocol/openid-connect/token"
KEYCLOAK_API_ENDPOINT = \
    "{url}/auth/admin/realms/{realm}"


def get_api_key(connection_data, url, realm):

    endpoint = KEYCLOAK_TOKEN_ENDPOINT.format(url=url, realm=realm)
    response = requests.post(endpoint, data=connection_data)

    if response.ok:
        return json.loads(response.text)["access_token"]
    elif response.status_code == 401:
        raise KeycloakAuthenticationError(
            ("Couldn't authenticate with Keycloak user '{}'. Is your"
             " password correct?").format(connection_data["username"]),
            endpoint)
    else:
        raise KeycloakCommunicationError((f"Failed to retrieve API token:"
            f" got {response.status_code} response."), endpoint)


def load_users(connection_data):

    with Connection(**connection_data) as connection:

        keycloak_users = []
        for user in connection.load_users(User):
            keycloak_users.append(user.as_keycloak_user())

        return keycloak_users


def parse_permissions(users):

    groups = set()
    roles = set()

    for user in users:
        for permission in user.permissions:

            groups.add(permission.group)
            roles.add(permission.role)

    return groups, roles


def populate_keycloak(users, url, realm, api_key):

    api_endpoint = KEYCLOAK_API_ENDPOINT.format(url=url, realm=realm)
    users_endpoint = f"{api_endpoint}/users"
    groups_endpoint = f"{api_endpoint}/groups"
    roles_endpoint = f"{api_endpoint}/roles"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # Determine unique roles and groups to add to Keycloak from
    # parsed user permissions
    print(f"Calculating unique groups and roles.")
    groups, roles = parse_permissions(users)

    print(f"Loading groups into Keycloak.")
    for group in groups:

        data = {"name": group}
        response = requests.post(groups_endpoint, headers=headers, data=data)

        if not response.ok:
            raise KeycloakCommunicationError((f"Got {response.status_code}"
                f" response attempting to load group '{group}'"),
                groups_endpoint)

    print(f"Loading roles into Keycloak.")
    for role in roles:

        data = {"name": role}
        response = requests.post(roles_endpoint, headers=headers, data=data)

        if not response.ok:
            raise KeycloakCommunicationError((f"Got {response.status_code}"
                f" response attempting to load role '{role}'"),
                roles_endpoint)

    loaded_count = 0
    existing_count = 0
    for user in users:

        data = user.data
        response = requests.post(users_endpoint, headers=headers, data=data)

        if response.ok:
            loaded_count += 1

        elif response.status_code == 409:
            print(f"User '{user}' already exists, cannot overwrite.")
            existing_count += 1

        else:
            raise KeycloakCommunicationError((f"Got {response.status_code}"
                f" response attempting to load user '{user}'"), users_endpoint)

    return loaded_count, existing_count


@click.command()
@click.option("-k", "--keycloak_url", required=True,
              help=("The URL of the Keycloak server."))
@click.option("-r", "--keycloak_realm", required=True,
              help="The Keycloak realm ID, e.g. 'master'")
@click.option("-u", "--keycloak_user", required=True,
              help="The Keycloak admin API user.")
@click.option("--keycloak_password", prompt=True, hide_input=True)
@click.option("-H", "--database_host", default="localhost",
              help="The database host.")
@click.option("-p", "--database_port", default="5432",
              help="The database port.")
@click.option("-d", "--database_name", required=True,
              help="The source database name.")
@click.option("-U", "--database_user",
              help="The database user.")
@click.option("--database_password", prompt=True, hide_input=True)
def main(keycloak_url, keycloak_realm, keycloak_user, keycloak_password,
        database_host, database_port, database_name, database_user,
        database_password):

    # Setup database connection values
    database_connection_data = {
        "user": database_user,
        "password": database_password,
        "host": database_host,
        "port": database_port,
        "database": database_name,
    }

    # Attempt to parse Keycloak-compatible user objects from the database
    print(f"Beginning user discovery...")
    users = None
    try:
        users = load_users(database_connection_data)
        print(f"Discovered {len(users)} users.")

    except ProgrammingError as e:

        LOG.error("Error connecting to the database: {}".format(str(e)))
        return

    if not users:

        print("Nothing to do.")
        return

    # Setup Keycloak API token request
    keycloak_token_request_data = {
        "client_id": "admin-cli",
        "grant_type": "password",
        "username": keycloak_user,
        "password": keycloak_password
    }

    keycloak_url = keycloak_url.rstrip('/')

    # Attempt to populate the Keycloak server with discovered users
    print(f"Importing users into Keycloak...")
    try:
        api_key = get_api_key(
            keycloak_token_request_data, keycloak_url, keycloak_realm)
        print("Retrieved API access token.")

        loaded_count, existing_count = populate_keycloak(
            users, keycloak_url, keycloak_realm, api_key)

        message = f"Loaded {loaded_count} out of {len(users)} users."
        if existing_count > 0:
            message = (f"{message} {existing_count} users were already in"
                " Keycloak and did not get overwritten.")
        print(message)

    except ConnectionError:
        LOG.error(("Couldn't connect to Keycloak server '{}'."
            ).format(keycloak_url))
        return

    except KeycloakCommunicationError as e:
        LOG.error(str(e))
        return

    except KeycloakAuthenticationError as e:
        LOG.error(("").format(keycloak_user))
        return


if __name__ == "__main__":

    main()

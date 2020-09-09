""" Script to run the migration. """

__author__ = "William Tucker"
__date__ = "2020-08-04"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import click
import click_config_file
import logging
import importlib

from requests.exceptions import ConnectionError
from sqlalchemy.exc import ProgrammingError

from usermigrate.db import Connection
from usermigrate.keycloak import KeycloakApi, parse_groups
from usermigrate.keycloak.exceptions import KeycloakAuthenticationError, \
    KeycloakCommunicationError, KeycloakConflictError


LOG = logging.getLogger(__name__)

DEFAULT_USER_MODEL = "usermigrate.db.models.User"


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
@click.option("-m", "--user_model", default=DEFAULT_USER_MODEL,
              help=("Python import path to a valid SQLAlchemy model"
                    " representing a Keycloak user."))
@click_config_file.configuration_option()
def main(keycloak_url, keycloak_realm, keycloak_user, keycloak_password,
        database_host, database_port, database_name, database_user,
        database_password, user_model):
    """ Migrates users and groups from a specified database into Keycloak.
    Will not overwrite existing users or groups. """

    # Load the SQLAlchemy user model
    module_name, _, class_name = user_model.rpartition('.')
    user_model_module = importlib.import_module(module_name)
    user_model_class = getattr(user_model_module, class_name)

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
    users = []
    try:

        with Connection(**database_connection_data) as connection:

            database_users = connection.load_users(user_model_class)
            for user in database_users:
                users.append(user.data)

        print(f"Discovered {len(users)} users.")

    except ProgrammingError as e:

        LOG.error("Error connecting to the database: {}".format(str(e)))
        return

    if not users:

        print("Nothing to do.")
        return

    # Determine unique groups to add to Keycloak
    groups = parse_groups(users)

    keycloak_url = keycloak_url.rstrip('/')

    # Attempt to populate the Keycloak server with discovered users
    print(f"Importing users into Keycloak...")
    try:

        with KeycloakApi(keycloak_url, keycloak_realm, keycloak_user, \
            keycloak_password) as api:

            populate_keycloak(api, users, groups)

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


def populate_keycloak(api, users, groups):
    """ Imports a set of Keycloak compatible users into Keycloak. """

    print(f"Importing groups into Keycloak.")
    for group in groups:

        try:
            api.post_group(group)

        except KeycloakConflictError:
            print(f"Group '{group}' already exists, skipping.")

    print(f"Importing users into Keycloak.")
    loaded_count = 0
    existing_count = 0
    for user in users:

        try:
            success = api.post_user(user)
            if success:
                loaded_count += 1

        except KeycloakConflictError:
            print(f"User '{user}' already exists, cannot overwrite.")
            existing_count += 1

    message = f"Imported {loaded_count} out of {len(users)} users."
    if existing_count > 0:
        message = (f"{message} {existing_count} users were already in"
            " Keycloak and did not get overwritten.")
    print(message)


if __name__ == "__main__":

    main()

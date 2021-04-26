""" Script to run the migration. """

__author__ = "William Tucker"
__date__ = "2020-08-04"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import click
import click_config_file
import logging
import importlib
import urllib3

from requests.exceptions import ConnectionError
from sqlalchemy.exc import ProgrammingError
from tqdm import tqdm

from usermigrate.db import Connection
from usermigrate.keycloak import KeycloakApi
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
@click.option("--cacert", required=False,
              help="Certificate file path for verifying the Keycloak connection.")
@click.option("--insecure", default=False,
              help="Ignore Keycloak server certificate verification.")
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
        cacert, insecure, database_host, database_port, database_name,
        database_user, database_password, user_model):
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

    # Keycloak API connection setup
    verify = not insecure
    if cacert:
        verify = cacert
    keycloak_url = keycloak_url.rstrip('/')
    keycloak_api = KeycloakApi(keycloak_url, keycloak_realm, keycloak_user, \
        keycloak_password, verify=verify)

    # Check Keycloak connection
    print(f"Checking connection to Keycloak server at '{keycloak_url}'")
    try:
        keycloak_api.check_connection()

    except ConnectionError as e:
        LOG.error(("Failed to connect to Keycloak server: {}").format(e))
        return

    # Attempt to parse Keycloak-compatible user objects from the database
    print(f"Discovering user and group data from the database...")
    users, groups = discover(database_connection_data, user_model_class)

    if not users:

        print("Nothing to do.")
        return

    # Attempt to populate the Keycloak server with discovered users
    print("Starting import...")
    try:

        with keycloak_api:

            # Suppress redundant insecure request warnings
            if insecure:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            minutes_left, _ = divmod(keycloak_api.access_expires, 60)
            print(f"Keycloak access token will last {minutes_left} minutes.")

            populate_keycloak(keycloak_api, users, groups)

    except ConnectionError as e:
        LOG.error(("Couldn't connect to Keycloak server '{}'. Error was: {}"
            ).format(keycloak_url, e))
        return

    except KeycloakCommunicationError as e:
        LOG.error(str(e))
        return

    except KeycloakAuthenticationError as e:
        LOG.error(("").format(keycloak_user))
        return


def discover(database_connection_data, user_model_class):
    """ Discover users and groups from a database. """

    users = []
    groups = set()
    try:

        with Connection(**database_connection_data) as connection:

            database_users = connection.load_users(user_model_class)
            for user in database_users:

                user_data = user.data
                users.append(user_data)
                for group in user_data["groups"]:
                    groups.add(group)

    except ProgrammingError as e:

        LOG.error("Error connecting to the database: {}".format(str(e)))
        return

    print(f"Discovered {len(users)} users and {len(groups)} groups.")

    return users, groups


def populate_keycloak(api, users, groups):
    """ Imports a set of Keycloak compatible users into Keycloak. """

    print(f"Importing {len(groups)} groups into Keycloak.")
    loaded_count = 0
    existing_count = 0
    failed_count = 0
    for group in tqdm(groups):

        try:
            success = api.post_group(group)
            if success:
                loaded_count += 1

        except KeycloakConflictError:
            LOG.debug(f"Group '{group}' already exists, skipping.")
            existing_count += 1

        except Exception as e:
            LOG.error(f"Failed to import group '{group}', error was: {str(e)}")
            failed_count += 1

    message = (f"Imported {loaded_count} out of {len(groups)} groups."
        f" There were {failed_count} failures.")
    if existing_count > 0:
        message = (f"{message} {existing_count} groups were already in"
            " Keycloak and did not get overwritten.")
    print(message)

    print(f"Importing {len(users)} users into Keycloak.")
    loaded_count = 0
    existing_count = 0
    failed_count = 0
    for user in tqdm(users):

        try:
            success = api.post_user(user)
            if success:
                loaded_count += 1

        except KeycloakConflictError:
            LOG.debug(f"User '{user}' already exists, cannot overwrite.")
            existing_count += 1

        except Exception as e:
            LOG.error(f"Failed to import user '{user}', error was: {str(e)}")
            failed_count += 1

    message = (f"Imported {loaded_count} out of {len(users)} users."
        f" There were {failed_count} failures.")
    if existing_count > 0:
        message = (f"{message} {existing_count} users were already in"
            " Keycloak and did not get overwritten.")
    print(message)


if __name__ == "__main__":

    main()

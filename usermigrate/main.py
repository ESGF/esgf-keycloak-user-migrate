""" Script to run the migration. """

__author__ = "William Tucker"
__date__ = "2020-08-04"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import click
import click_config_file
import importlib
import json
import logging
import os
import time
import urllib3
import yaml

from enum import Enum
from functools import partial, partialmethod
from multiprocessing import Pool
from sqlalchemy.exc import ProgrammingError
from tqdm import tqdm
from tqdm.contrib.concurrent import process_map

from usermigrate.db import Connection
from usermigrate.keycloak import KeycloakApi
from usermigrate.keycloak.exceptions import KeycloakAuthenticationError, \
    KeycloakCommunicationError, KeycloakUsernameConflictError, \
    KeycloakConflictError


LOG = logging.getLogger(__name__)

DEFAULT_USER_MODEL = "usermigrate.db.models.User"


def yaml_config_provider(file_path, cmd_name):
    settings = None
    with open(file_path, 'r') as config_data:
        return yaml.safe_load(config_data)


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
@click.option("-f", "--file_input",
              help="Path to a JSON file containing a list of users to import.")
@click.option("--skip-cache", default=False,
              help="Skip checking for previously cached users.")
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
@click.option("--filter", "-x", type=(str, str), multiple=True)
@click.option("-o", "--overwrite", default=False,
              help="Overwrite existing Keycloak users.")
@click.option("-v", "--verbose", default=False,
              help="Overwrite existing Keycloak users.")
@click_config_file.configuration_option(provider=yaml_config_provider)
def main(keycloak_url, keycloak_realm, keycloak_user, keycloak_password,
        cacert, insecure, file_input, skip_cache, database_host, database_port,
        database_name, database_user, database_password, user_model, filter,
        overwrite, verbose):
    """ Migrates users and groups from a specified database into Keycloak.
    Will not overwrite existing users or groups. """

    # Load the SQLAlchemy user model
    module_name, _, class_name = user_model.rpartition('.')
    user_model_module = importlib.import_module(module_name)
    user_model_class = getattr(user_model_module, class_name)

    filter_kwargs = dict(filter)

    # Disable tqdm if not in verbose mode
    if not verbose:
        tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)

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

    # Discover users
    cache_file_path = os.path.abspath("./user_cache")

    if file_input:
        print(f"Reading users from input file {file_input}...")

    elif not skip_cache and not file_input and os.path.exists(cache_file_path):

        print(f"Found cached users at {cache_file_path}.")
        response = None
        while response not in ["y", "n"]:
            response = input(("Skip database discovery and import from cache?"
                " y/n\n")).lower()

        if response == "y":
            file_input = cache_file_path

        elif response == "n":
            print("Rediscovering.")

    if not file_input:

        file_input = cache_file_path
        if os.path.exists(cache_file_path):
            print("Removing old cache.")
            os.remove(cache_file_path)

        # Attempt to parse Keycloak-compatible user objects from the database
        print(f"Discovering users from the database...")
        try:
            discover(database_connection_data, user_model_class, cache_file_path, filter_kwargs=filter_kwargs)

        except Exception as e:

            print("Cleaning up failed cache")
            os.remove(cache_file_path)
            return

    users = []
    try:
        with open(file_input) as users_file:
            for line in users_file:
                users.append(json.loads(line))
    except Exception as e:
        LOG.error(f"Failed to load users from {file_input}: {e}")
        return

    if not users:
        print("No users found.\nNothing to do.")
        return

    print("Parsing groups from users...")
    groups = set()
    for user in users:
        for group in user["groups"]:
            groups.add(group)

    print(f"{len(users)} users and {len(groups)} unique groups found.")

    # Attempt to populate the Keycloak server with discovered users
    print("Starting import...")
    try:

        with keycloak_api:

            # Suppress redundant insecure request warnings
            if insecure:
                urllib3.disable_warnings(
                    urllib3.exceptions.InsecureRequestWarning)

            populate_groups(keycloak_api, groups, verbose=verbose)
            populate_users(keycloak_api, users, overwrite, verbose=verbose)

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


def discover(database_connection_data, user_model_class, cache_file_path, filter_kwargs={}):
    """ Discover users from a database. """

    start = time.time()
    try:
        with Connection(**database_connection_data) as connection:

            database_users = connection.load_users(user_model_class, **filter_kwargs)
            for user in database_users:
                cache_object(cache_file_path, user.data)

    except ProgrammingError as e:

        LOG.error("Error connecting to the database: {}".format(str(e)))
        raise e

    except Exception as e:

        LOG.error(f"User discovery failed: {e}")
        raise e

    end = time.time()
    print((f"Database query completed in {int(end - start)} seconds."))
    print(f"Created user cache at {cache_file_path}")


def populate_groups(api, groups, verbose=False):

    added = 0
    for group in groups:

        try:
            api.create_group(group)
            added += 1

        except Exception as e:

            if verbose:
                print(f"Failed to import group {group}, error was: {e}")

    print(f"Added {added}/{len(groups)} groups to Keycloak.")


class ImportResult(Enum):

    FAILED = 0
    LOADED = 1
    UPDATED = 2
    EXISTS = 3
    CONFLICT = 4
    SKIPPED = 5


def try_populate_user(user, api, overwrite, log_file_path, retry_cache_path, verbose):

    username = user.get("username")
    if not username:
        username = ""
    email = user.get("email")
    if not email:
        email = ""

    message_template = f"{username},{email},{{0}}"

    if not username:

        message = message_template.format(
            "Can't import user because the username field is missing.")
        write_log_message(log_file_path, message)
        cache_object(retry_cache_path, user)

        return ImportResult.SKIPPED

    if not email:

        message = message_template.format(
            "Can't import user because the email field is missing.")
        write_log_message(log_file_path, message)
        cache_object(retry_cache_path, user)

        return ImportResult.SKIPPED

    try:

        created = api.create_user(user, overwrite=overwrite)
        if created:
            return ImportResult.LOADED
        else:
            return ImportResult.UPDATED

    except KeycloakUsernameConflictError:

        if verbose:
            message = message_template.format(
                "User with the same username already exists.")
            write_log_message(log_file_path, message)

        return ImportResult.EXISTS

    except KeycloakConflictError:

        message = message_template.format(
            "Failed to import user due to a data conflict.")
        write_log_message(log_file_path, message)
        cache_object(retry_cache_path, user)

        return ImportResult.CONFLICT

    except Exception as e:

        message = message_template.format(
            f"Failed to import user, error was {e}")
        write_log_message(log_file_path, message)
        cache_object(retry_cache_path, user)

        return ImportResult.FAILED


def populate_users(api, users, overwrite, verbose=False):
    """ Imports a set of Keycloak compatible objects into Keycloak. """

    print(f"Starting user import.")

    log_file_path = os.path.abspath(f"user_import_failures.csv")
    if os.path.exists(log_file_path):
        print(f"Removing previous log file.")
        os.remove(log_file_path)

    retry_cache_path = os.path.abspath(f"user_retry_cache")
    if os.path.exists(retry_cache_path):
        print(f"Removing previous retry cache.")
        os.remove(retry_cache_path)

    print(f"Writing errors to {log_file_path}.")

    print(f"Importing {len(users)} user objects into Keycloak.")

    loop_kwargs = {
        "api": api,
        "overwrite": overwrite,
        "log_file_path": log_file_path,
        "retry_cache_path": retry_cache_path,
        "verbose": verbose,
    }
    loop_function = partial(try_populate_user, **loop_kwargs)
    results = process_map(loop_function, users, max_workers=8, chunksize=1)

    report = {
        ImportResult.FAILED: 0,
        ImportResult.LOADED: 0,
        ImportResult.UPDATED: 0,
        ImportResult.EXISTS: 0,
        ImportResult.CONFLICT: 0,
        ImportResult.SKIPPED: 0,
    }
    for result in results:
        report[result] += 1

    loaded_count = report[ImportResult.LOADED]
    updated_count = report[ImportResult.UPDATED]
    existing_count = report[ImportResult.EXISTS]
    conflict_count = report[ImportResult.CONFLICT]
    skipped_count = report[ImportResult.SKIPPED]
    failed_count = report[ImportResult.FAILED]

    problems_count = failed_count + conflict_count + skipped_count

    # Compile report
    message = f"Finished importing {len(users)} user records.\n---"

    # Number of created or updated/existing users
    if loaded_count > 0:
        message = f"{message}\nCreated {loaded_count} new users in Keycloak."
    if updated_count > 0:
        message = (f"{message}\n{updated_count} records matched existing"
            " Keycloak users and the Keycloak users were updated")
    if existing_count > 0:
        message = (f"{message}\n{existing_count} records matched existing"
            " Keycloak users and were skipped.")

    # Import problems or missing data
    if problems_count > 0:
        message = f"{message}\n---\nThere were {problems_count} problems:"
    if skipped_count > 0:
        message = (f"{message}\n{skipped_count} records were"
            " skipped because the name or email field was missing or blank.")
    if conflict_count > 0:
        message = (f"{message}\n{conflict_count} records"
            " weren't imported due to a data conflict.")
    if failed_count > 0:
        message = (f"{message}\n{failed_count} records"
            " weren't imported due to an unknown error.")
    if problems_count > 0:
        message = (f"{message}\nRerun with '-f {retry_cache_path}' to retry"
            f" {problems_count} skipped or failed users.")

    if verbose and os.path.exists(log_file_path):

            print("Log output:\n----")
            with open(log_file_path, "r") as log_file:
                for line in log_file:
                    print(line.strip())
            print("----")

    print(message)


def write_log_message(log_file_path, message):
    """ Appends a message to the end of a log file. """

    with open(log_file_path, "a") as log_file:
        log_file.write(f"{message}\n")


def cache_object(cache_file_path, object_data):
    """ Write an object dict to a file of a file. """

    add_new_line = False
    if os.path.exists(cache_file_path):
        add_new_line = True

    with open(cache_file_path, "a") as cache_file:

        if add_new_line:
            cache_file.write("\n")
        cache_file.write(json.dumps(object_data))


if __name__ == "__main__":

    main()

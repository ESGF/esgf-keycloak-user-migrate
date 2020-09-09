# ESGF Keycloak User Migration

Scripts for migrating a set of users into Keycloak. Allows a customisable SQLAlchemy model to be used to support arbitrary sources of user data.

## How to Use

The script can be run as a module:

```sh
python -m usermigrate
```

A configuration file can be added with the `--config` option. A template for this file is provided in the root of this repository, named "settings.py.template".

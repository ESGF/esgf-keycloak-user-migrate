""" Database interaction class. """

__author__ = "William Tucker"
__date__ = "2020-08-06"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


CONNECTION_TEMPLATE = \
    "postgresql+pg8000://{user}:{password}@{host}:{port}/{database}"


class Connection:

    def __init__(self, **kwargs):

        self._engine = create_engine(
            CONNECTION_TEMPLATE.format(**kwargs),
            isolation_level="READ UNCOMMITTED"
        )

    def __enter__(self):

        Session = sessionmaker(bind=self._engine)
        self._session = Session()

        return self

    def __exit__(self, *args):

        self._session.commit()
        self._session.close()

    def load_users(self, user_model, **filter_kwargs):

        query = self._session.query(user_model)
        return query.filter_by(**filter_kwargs)

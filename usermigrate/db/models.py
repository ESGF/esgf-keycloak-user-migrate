""" Generic table model creation. """

__author__ = "William Tucker"
__date__ = "2020-08-11"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


from sqlalchemy import Column, Table, MetaData, String, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import mapper, relationship

from usermigrate import KeycloakUser, KeycloakPermission


Base = declarative_base()


class Permission(Base):

    __tablename__ = "permission"
    __table_args__ = {"schema": "esgf_security"}

    id = Column(Integer, primary_key=True)

    group_id = Column("group_id", Integer, ForeignKey("esgf_security.group.id"))
    group = relationship("Group", back_populates="permissions")

    role_id = Column("role_id", Integer, ForeignKey("esgf_security.role.id"))
    role = relationship("Role", back_populates="permissions")

    user_id = Column("user_id", Integer, ForeignKey("esgf_security.user.id"))
    user = relationship("User", back_populates="permissions")


class Group(Base):

    __tablename__ = "group"
    __table_args__ = {"schema": "esgf_security"}

    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(String)

    permissions = relationship("Permission", back_populates="group")


class Role(Base):

    __tablename__ = "role"
    __table_args__ = {"schema": "esgf_security"}

    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(String)

    permissions = relationship("Permission", back_populates="role")


class User(Base):

    __tablename__ = "user"
    __table_args__ = {"schema": "esgf_security"}

    id = Column(Integer, primary_key=True)

    username = Column(String)       # username
    firstname = Column(String)      # first name
    middlename = Column(String)     # first name
    lastname = Column(String)       # last name
    email = Column(String)          # email

    # permissions
    permissions = relationship("Permission", back_populates="user")

    def as_keycloak_user(self):

        keycloak_permissions = []
        for permission in self.permissions:

            keycloak_permission = KeycloakPermission(
                permission.group.name, permission.role.name)
            keycloak_permissions.append(keycloak_permission)

        return KeycloakUser(
            self.username,
            f"{self.firstname} {self.middlename}",
            self.lastname,
            self.email,
            keycloak_permissions
        )

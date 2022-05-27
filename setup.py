from setuptools import setup, find_packages

setup(
    name="esgf-keycloak-user-migrate",
    version="0.1",
    description="Placeholder",
    long_description="Placeholder",
    url="https://github.com/cedadev",
    author="William Tucker",
    author_email="william.tucker@stfc.ac.uk",
    license="BSD",
    packages=find_packages(),
    install_requires = [
        "click",
        "click-config-file",
        "pg8000",
        "requests",
        "sqlalchemy",
        "tqdm",
        "pyyaml",
    ]
)

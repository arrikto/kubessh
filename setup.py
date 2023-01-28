# Copyright © 2023 Arrikto Inc.  All Rights Reserved.

"""Setup file for KubeSSH."""

import os
from setuptools import setup, find_packages


INSTALL_REQUIRES = []

TESTS_REQUIRE = []

VERSION = "0.0.1"


def find_package_data(src_path):
    """Recursively collect all files under the given path as package data.

    The first component of the path is interpreted as the package name.

    The result is a list of all files under the given directory, relative to
    the source directory of the package.
    """
    package_name = src_path.split(os.path.sep)[0]

    package_data = []
    for path, dirs, files in os.walk(src_path, followlinks=True):
        rel_path = os.path.relpath(path, package_name)
        package_data.extend(os.path.join(rel_path, f) for f in files)

    return package_data


setup(
    name="kubessh",
    version=VERSION,
    description="KubeSSH",

    zip_safe=False,
    packages=find_packages(".", exclude=["tests"]),
    package_data={},
    install_requires=INSTALL_REQUIRES,
    tests_require=TESTS_REQUIRE,
    entry_points={
        "console_scripts": ["kubessh = kubessh.kubessh:main"]
    }
)

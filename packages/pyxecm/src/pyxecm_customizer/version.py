"""Version reported by the customizer (run history push and the API's OpenAPI info)."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import importlib.metadata
import os

# Set by the container build (container/Dockerfile_pyxecm) to the git commit the image was built from.
GIT_COMMIT_ENV = "PYXECM_GIT_COMMIT"

# Placeholder version in pyproject.toml. The container installs pyxecm from source, so it
# reports this instead of a release number - the git commit identifies the build instead.
UNRELEASED_VERSION = "0.0.0"


def customizer_version() -> str:
    """Return the installed pyxecm version, or the build's git commit for an unreleased build."""

    try:
        package_version = importlib.metadata.version("pyxecm")
    except importlib.metadata.PackageNotFoundError:
        package_version = "unknown"

    if package_version in (UNRELEASED_VERSION, "unknown"):
        git_commit = os.environ.get(GIT_COMMIT_ENV, "").strip()
        if git_commit:
            return git_commit

    return package_version

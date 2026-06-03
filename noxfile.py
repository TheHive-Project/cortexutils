import os

import nox

PROJECT_DIR = os.path.dirname(__file__)
CORTEXUTILS_DIR = os.path.join(PROJECT_DIR, "cortexutils/")
TESTS_DIR = os.path.join(PROJECT_DIR, "tests/")

nox.options.default_venv_backend = "none"
nox.options.keywords = "ci and not test"


@nox.session(tags=["ci", "lint"])
def style(session: nox.Session):
    """Run style checks with ruff."""
    session.run("ruff", "check", CORTEXUTILS_DIR, TESTS_DIR, __file__)


@nox.session(tags=["ci", "lint"])
def format(session: nox.Session):
    """Run format checks with ruff."""
    session.run("ruff", "format", "--check", CORTEXUTILS_DIR, TESTS_DIR, __file__)


@nox.session(tags=["ci", "lint"])
def type(session: nox.Session):
    """Run type checks with mypy."""
    session.run("mypy", "--install-types", "--non-interactive", CORTEXUTILS_DIR)


@nox.session(tags=["ci", "audit"])
def cve(session: nox.Session):
    """Run cve checks with pip-audit."""
    session.run("pip-audit", PROJECT_DIR)


@nox.session(tags=["ci", "audit"])
def security(session: nox.Session):
    """Run security checks with bandit."""
    session.run("bandit", "-r", CORTEXUTILS_DIR)


@nox.session(tags=["ci", "test"])
def test(session: nox.Session):
    """Run unit tests with pytest."""

    if not session.posargs:
        session.run("pytest", "-v", "--cov")
    else:
        session.run("pytest", *session.posargs)


@nox.session(tags=["cd", "build"])
def build(session: nox.Session):
    """Build with the build module."""
    session.run("rm", "-rf", "build/", "dist/")
    session.run("python", "-m", "build", "--sdist", "--wheel")


@nox.session(tags=["cd", "upload"])
def upload(session: nox.Session):
    """Upload to PyPI using twine."""

    session.run(
        "bash",
        "-c",
        r"""
        TAG=${GITHUB_REF#refs/*/}
        VERSION=$(grep -Po '(?<=version = ")[^"]*' pyproject.toml)
        if [ "$TAG" != "$VERSION" ]; then
          echo "Tag value and package version are different: ${TAG} != ${VERSION}"
          exit 1
        else
          echo "Matching tag value and package version!"
        fi
        """,
    )
    session.run("twine", "upload", "dist/*")

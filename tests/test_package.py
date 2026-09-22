"""Package installation and command smoke tests."""

from security_triage_agent import __version__
from security_triage_agent.__main__ import main


def test_package_version() -> None:
    assert __version__ == "1.0.0"


def test_foundation_check_starts_without_credentials() -> None:
    assert main(["--check"]) == 0

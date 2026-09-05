"""Legacy unit handlers use explicit auth-disabled mode; auth suites opt in."""
import os
os.environ.setdefault('OSINT_TOOLS_DATA_DIR','/tmp/osint-tools-test-import')
import pytest

@pytest.fixture(autouse=True)
def legacy_local_context(monkeypatch):
    from osint_tools import server
    monkeypatch.setattr(server,'AUTH_ENABLED',False)

import pytest
from starlette.testclient import TestClient

from ofcli.api import app


@pytest.fixture()
def test_api():
    test_api = TestClient(app)
    yield test_api

import pytest


@pytest.mark.parametrize(
    "entity_id, ret_code",
    [
        ("", 400),
        ("invalid_url", 400),
        ("ftp://example.com", 400),
        ("https://example.com", 500),
    ],
)
def test_invalid_url(test_api, entity_id, ret_code):
    response = test_api.get(f"/entity/{entity_id}")
    assert response.status_code == ret_code


def test_missing_params(test_api):
    response = test_api.get("/fetch/")
    assert response.status_code == 400

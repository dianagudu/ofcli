from pydantic import HttpUrl
import pytest

from ofcli.utils import URL, well_known_url, subtree_to_string


@pytest.mark.parametrize(
    "test_url_str, other_url",
    [
        ("https://example.com", "https://example.com"),
        ("https://example.com", URL("https://example.com")),
        ("https://example.com", HttpUrl("https://example.com")),
        ("https://example.com", "https://example.com/"),
        ("https://example.com", URL("https://example.com/")),
        ("https://example.com", HttpUrl("https://example.com/")),
        ("https://example.com/", "https://example.com"),
        ("https://example.com/", URL("https://example.com")),
        ("https://example.com/", HttpUrl("https://example.com")),
        ("https://example.com/", "https://example.com/"),
        ("https://example.com/", URL("https://example.com/")),
        ("https://example.com/", HttpUrl("https://example.com/")),
    ],
)
def test_url_equal(test_url_str, other_url):
    assert URL(test_url_str) == other_url


@pytest.mark.parametrize(
    "test_url_str, other_url",
    [
        ("https://example.com", "https://example.org"),
        ("https://example.com", "http://example.com"),
        ("https://example.com", "https://example.com/other"),
    ],
)
def test_url_not_equal(test_url_str, other_url):
    assert URL(test_url_str) != other_url


@pytest.mark.parametrize(
    "test_url_str, result_str",
    [
        ("https://example.com", "https://example.com"),
        ("https://example.com/", "https://example.com"),
        ("https://example.com//", "https://example.com"),
        ("https://example.com/path/", "https://example.com/path"),
        ("https://example.com/?param=value", "https://example.com?param=value"),
    ],
)
def test_url_remove_trailing_slashes(test_url_str, result_str):
    assert URL(test_url_str).remove_trailing_slashes() == result_str


@pytest.mark.parametrize(
    "test_url_str, params, result_str",
    [
        ("https://example.com", {"param": "value"}, "https://example.com?param=value"),
        (
            "https://example.com/path",
            {"param": "value"},
            "https://example.com/path?param=value",
        ),
        (
            "https://example.com?param=value",
            {"param": "value"},
            "https://example.com?param=value",
        ),
        (
            "https://example.com?param=value",
            {"param": "other"},
            "https://example.com?param=other",
        ),
        (
            "https://example.com?param=value",
            {"param": "other", "param2": "value2"},
            "https://example.com?param=other&param2=value2",
        ),
        (
            "https://example.com",
            {"sub": "https://op.com", "iss": "https://ta.com"},
            "https://example.com?sub=https://op.com&iss=https://ta.com",
        ),
    ],
)
def test_url_add_query_params(test_url_str, params, result_str):
    assert URL(test_url_str).add_query_params(params) == URL(result_str)


def test_url_raises():
    with pytest.raises(ValueError):
        URL("not a url")


@pytest.mark.parametrize(
    "url, result",
    [
        ("https://example.com", "https://example.com/.well-known/openid-federation"),
        ("https://example.com/", "https://example.com/.well-known/openid-federation"),
        (
            "https://example.com/path",
            "https://example.com/path/.well-known/openid-federation",
        ),
        (
            "https://example.com/path/",
            "https://example.com/path/.well-known/openid-federation",
        ),
        (
            "https://example.com/path/?param=value",
            "https://example.com/path/.well-known/openid-federation?param=value",
        ),
    ],
)
def test_well_known_url(url, result):
    assert result == well_known_url(url)


def test_well_known_url_raises():
    with pytest.raises(ValueError):
        well_known_url(URL("not a url"))


@pytest.mark.parametrize(
    "subtree, result",
    [
        ({}, ""),
        (
            {
                "op": {
                    "entity_type": "openid_provider",
                    "entity_configuration": "op jwt",
                }
            },
            "- op (openid_provider)\n",
        ),
        (
            {
                "ta": {
                    "entity_type": "federation_entity",
                    "entity_configuration": "ta jwt",
                    "subordinates": {
                        "rp": {
                            "entity_type": "openid_relaying_party",
                            "entity_configuration": "rp jwt",
                        }
                    },
                }
            },
            "- ta (federation_entity)\n  - rp (openid_relaying_party)\n",
        ),
        (
            {
                "ta": {
                    "entity_type": "federation_entity",
                    "entity_configuration": "ta jwt",
                    "subordinates": {
                        "rp": {
                            "entity_type": "openid_relaying_party",
                            "entity_configuration": "rp jwt",
                        },
                        "ia": {  # intermediate authority
                            "entity_type": "federation_entity",
                            "entity_configuration": "ia jwt",
                            "subordinates": {
                                "op": {
                                    "entity_type": "openid_provider",
                                    "entity_configuration": "op jwt",
                                }
                            },
                        },
                    },
                }
            },
            "- ta (federation_entity)\n  - rp (openid_relaying_party)\n  - ia (federation_entity)\n    - op (openid_provider)\n",
        ),
    ],
)
def test_subtree_to_string(subtree, result):
    assert result == subtree_to_string(subtree)

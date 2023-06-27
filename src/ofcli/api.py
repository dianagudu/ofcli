"""
API for OIDC Federation exploration.
"""

import urllib.parse
import requests
import json

from ofcli import utils
from ofcli.message import EntityStatement, Metadata


def get_entity_configuration(
    entity_id: str, verify: bool = False, verify_ssl: bool = True
) -> dict:
    """Fetches an entity configuration from a given entity ID.

    :param entity_id: The entity ID to fetch the entity configuration from (URL).
    :param verify: Whether to verify the entity configuration. Defaults to False.
    :param verify_ssl: Whether to verify the SSL certificate of the entity ID. Defaults to True.
    :return: The decoded entity configuration as a dictionary.
    """
    configuration = utils.get_self_signed_entity_configuration(
        entity_id, verify_ssl=verify_ssl
    )
    if verify:
        EntityStatement(**configuration).verify()
    return configuration


def get_entity_metadata(
    entity_id: str, verify: bool = False, verify_ssl: bool = True
) -> dict:
    """Fetches the OIDC metadata of a given entity ID.

    :param entity_id: The entity ID to fetch the OIDC metadata from (URL).
    :param verify: Whether to verify the metadata. Defaults to False.
    :param verify_ssl: Whether to verify the SSL certificate of the entity ID. Defaults to True.
    :return: The decoded OIDC metadata as a dictionary.
    """
    metadata = utils.get_self_signed_entity_configuration(
        entity_id, verify_ssl=verify_ssl
    ).get("metadata")
    if not metadata:
        raise Exception("No metadata found in entity configuration.")
    if verify:
        Metadata(**metadata).verify()
    return metadata


def get_entity_jwks(entity_id: str, verify_ssl: bool = True) -> dict:
    """Fetches the federation JWKS of a given entity ID.

    :param entity_id: The entity ID to fetch the JWKS from (URL).
    :param verify_ssl: Whether to verify the SSL certificate of the entity ID. Defaults to True.
    :return: The decoded JWKS as a dictionary.
    """
    jwks = utils.get_self_signed_entity_configuration(
        entity_id, verify_ssl=verify_ssl
    ).get("jwks")
    if not jwks:
        raise Exception("No jwks found in entity configuration.")
    return jwks


def get_trustchains(
    entity_id: str, trust_anchors: list[str] | None = None, verify_ssl: bool = True
) -> dict:
    """Builds all trustchains for a given entity ID.

    :param entity_id: The entity ID to build the trustchains for (URL).
    :param trust_anchors: The trust anchor to use for building the trustchains. If not set (None), all possible trust chains until the root are built.
    :param verify_ssl: Whether to verify the SSL certificate of the entity ID. Defaults to True.
    :return: The trustchains as a dictionary.
    """
    # entity_configuration_jws = utils.fetch_jws_from_url(
    #     utils.well_known_url(entity_id), verify_ssl=verify_ssl
    # )
    # chains = {}
    # authority_hints = entity_configuration.get("authority_hints", [])
    chains = utils.build_trustchains(entity_id, verify_ssl=verify_ssl)
    return {entity_id: chains}


def get_entity_statement(entity_id: str, issuer: str, verify_ssl: bool = True) -> dict:
    issuer_metadata = get_entity_metadata(entity_id=issuer, verify_ssl=verify_ssl)
    try:
        fe = issuer_metadata["federation_entity"]
    except KeyError:
        raise Exception("Leaf entities cannot publish statements about other entities.")
    try:
        fetch_url = fe["federation_fetch_endpoint"]
    except KeyError:
        raise Exception("No federation_fetch_endpoint found in metadata!")
    return utils.get_payload(
        utils.fetch_entity_statement(
            entity_id=entity_id, fetch_url=fetch_url, iss=issuer, verify_ssl=verify_ssl
        )
    )


def list_subordinates(
    entity_id: str,
    entity_type: str | None = None,
    trust_marked: bool = False,
    trust_mark_id: str | None = None,
    verify_ssl: bool = True,
) -> list:
    metadata = get_entity_metadata(entity_id=entity_id, verify_ssl=verify_ssl)
    try:
        le = metadata["federation_entity"]
    except KeyError:
        raise Exception("Leaf entities cannot have subordinates.")
    try:
        list_url = le["federation_list_endpoint"]
    except KeyError:
        raise Exception("No federation_list_endpoint found in metadata!")

    params = {}
    if entity_type:
        params["entity_type"] = entity_type
    if trust_marked:
        params["trust_marked"] = trust_marked
    if trust_mark_id:
        params["trust_mark_id"] = trust_mark_id
    url_parts = list(urllib.parse.urlparse(list_url))
    query = dict(urllib.parse.parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urllib.parse.urlencode(query)

    url = urllib.parse.urlunparse(url_parts)
    response = requests.request("GET", url, verify=verify_ssl)

    if response.status_code != 200:
        raise ValueError(
            "Could not fetch entity statement from %s. Status code: %s"
            % (url, response.status_code)
        )

    return json.loads(response.text)

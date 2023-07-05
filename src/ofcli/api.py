"""
API for OIDC Federation exploration.
"""

import requests
import json

from ofcli import utils
from ofcli.message import EntityStatement, Metadata
from ofcli.trustchain import TrustChain


def get_entity_configuration(entity_id: str, verify: bool = False) -> dict:
    """Fetches an entity configuration from a given entity ID.

    :param entity_id: The entity ID to fetch the entity configuration from (URL).
    :param verify: Whether to verify the entity configuration. Defaults to False.
    :return: The decoded entity configuration as a dictionary.
    """
    configuration = utils.get_self_signed_entity_configuration(entity_id)
    if verify:
        EntityStatement(**configuration).verify()
    return configuration


def get_entity_metadata(entity_id: str, verify: bool = False) -> dict:
    """Fetches the OIDC metadata of a given entity ID.

    :param entity_id: The entity ID to fetch the OIDC metadata from (URL).
    :param verify: Whether to verify the metadata. Defaults to False.
    :return: The decoded OIDC metadata as a dictionary.
    """
    metadata = utils.get_self_signed_entity_configuration(entity_id).get("metadata")
    if not metadata:
        raise Exception("No metadata found in entity configuration.")
    if verify:
        Metadata(**metadata).verify()
    return metadata


def get_entity_jwks(entity_id: str) -> dict:
    """Fetches the federation JWKS of a given entity ID.

    :param entity_id: The entity ID to fetch the JWKS from (URL).
    :return: The decoded JWKS as a dictionary.
    """
    jwks = utils.get_self_signed_entity_configuration(entity_id).get("jwks")
    if not jwks:
        raise Exception("No jwks found in entity configuration.")
    return jwks


def get_trustchains(
    entity_id: str, trust_anchors: list[str] = [], export: str | None = None
) -> list[TrustChain]:
    """Builds all trustchains for a given entity ID.

    :param entity_id: The entity ID to build the trustchains for (URL).
    :param trust_anchors: The trust anchor to use for building the trustchains. If not set (empty list), all possible trust chains until the root are built.
    :param export: The file to export the trustchains to. Defaults to None.
    :return: The trustchains as a list of lists of entity IDs.
    """
    return utils.build_trustchains(entity_id, trust_anchors, export)


def fetch_entity_statement(entity_id: str, issuer: str) -> dict:
    return utils.fetch_entity_statement(entity_id, issuer)


def list_subordinates(
    entity_id: str,
    entity_type: str | None = None,
    trust_marked: bool = False,
    trust_mark_id: str | None = None,
) -> dict:
    metadata = get_entity_metadata(entity_id=entity_id)
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

    url = utils.add_query_params(list_url, params)
    response = requests.request("GET", url, verify=utils.VERIFY_SSL)

    if response.status_code != 200:
        raise ValueError(
            "Could not fetch subordinates from %s. Status code: %s"
            % (url, response.status_code)
        )

    return json.loads(response.text)


def discover(entity_id: str, tas: list[str] = []) -> list[str]:
    """Discovers all OPs available in the federation to a given RP.

    :param entity_id: The entity ID to discover the OPs for (URL).
    :param tas: The trust anchors to use for discovery. Defaults to [].
    :return: The discovered OPs.
    """

    metadata = get_entity_metadata(entity_id=entity_id)
    # check if it is an openid_relying_party
    if not metadata.get("openid_relying_party"):
        raise Exception("Entity is not an OpenID Relying Party.")
    return utils.discover(entity_id, tas)


def resolve_entity(entity_id: str, ta: str) -> dict:
    """Resolves an entity ID's metadata given a trust anchor.

    :param entity_id: The entity ID to resolve (URL).
    :return: The resolved metadata.
    """
    return {}

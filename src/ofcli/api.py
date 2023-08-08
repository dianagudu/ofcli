"""
API for OIDC Federation exploration.
"""
from ofcli import utils, trustchain, fedtree
from ofcli.message import EntityStatement, Metadata


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
) -> list[trustchain.TrustChain]:
    """Builds all trustchains for a given entity ID.

    :param entity_id: The entity ID to build the trustchains for (URL).
    :param trust_anchors: The trust anchor to use for building the trustchains. If not set (empty list), all possible trust chains until the root are built.
    :param export: The file to export the trustchains to. Defaults to None.
    :return: The trustchains as a list of lists of entity IDs.
    """
    return trustchain.build_trustchains(entity_id, trust_anchors, export)


def fetch_entity_statement(entity_id: str, issuer: str) -> dict:
    return utils.fetch_entity_statement(entity_id, issuer)


def list_subordinates(
    entity_id: str,
    entity_type: str | None = None,
    trust_marked: bool = False,
    trust_mark_id: str | None = None,
) -> list[str]:
    entity = EntityStatement(**utils.get_self_signed_entity_configuration(entity_id))
    return utils.get_subordinates(entity, entity_type, trust_marked, trust_mark_id)


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
    ta_entities = []
    # if no trust anchors are given, infer them from building the trustchains
    if len(tas) == 0:
        chains = trustchain.build_trustchains(entity_id, [], export=None)
        if len(chains) == 0:
            raise Exception("Could not find any trust anchors.")
        for chain in chains:
            ta_entities.append(chain.get_trust_anchor())
    else:
        for ta in tas:
            ta_entities.append(
                EntityStatement(**utils.get_self_signed_entity_configuration(ta))
            )
    return fedtree.discover_ops(ta_entities)


def subtree(entity_id: str, export: str | None) -> dict:
    """Builds the entire federation subtree for given entity_id as root.

    :param entity_id: The entity ID to use as root for the subtree (URL)
    :return: The subtree serialized as a dict.
    """
    entity = EntityStatement(**utils.get_self_signed_entity_configuration(entity_id))
    tree = fedtree.discover(entity, export)
    return tree


def resolve_entity(entity_id: str, ta: str, entity_type: str) -> dict:
    """Resolves an entity ID's metadata given a trust anchor.

    :param entity_id: The entity ID to resolve (URL).
    :param ta: The trust anchor to use for resolving the entity ID.
    :param entity_type: The entity type to resolve.
    :return: The resolved metadata.
    """
    chains = trustchain.build_trustchains(entity_id, [ta], export=None)
    if len(chains) == 0:
        raise Exception("Could not build trustchain to trust anchor.")
    # TODO: select the shortest chain if more than one
    return chains[0].get_metadata(entity_type)

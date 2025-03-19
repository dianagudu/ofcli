"""
API for OIDC Federation exploration.
"""

import http
import aiohttp
from typing import Optional, List, Tuple
import pygraphviz
from ofcli import utils, trustchain, fedtree
from ofcli.utils import URL
from ofcli.message import EntityStatement, Metadata
from ofcli.exceptions import InternalException


async def get_entity_configuration(
    http_session: aiohttp.ClientSession, entity_id: str, verify: bool = False
) -> dict:
    """Fetches an entity configuration from a given entity ID.

    :param entity_id: The entity ID to fetch the entity configuration from (URL).
    :param verify: Whether to verify the entity configuration. Defaults to False.
    :return: The decoded entity configuration as a dictionary.
    """
    configuration = utils.get_payload(
        await utils.get_self_signed_entity_configuration(URL(entity_id), http_session)
    )
    if verify:
        EntityStatement(**configuration).verify()
    return configuration


async def get_entity_metadata(
    http_session: aiohttp.ClientSession, entity_id: str, verify: bool = False
) -> dict:
    """Fetches the OIDC metadata of a given entity ID.

    :param entity_id: The entity ID to fetch the OIDC metadata from (URL).
    :param verify: Whether to verify the metadata. Defaults to False.
    :return: The decoded OIDC metadata as a dictionary.
    """
    metadata = utils.get_payload(
        await utils.get_self_signed_entity_configuration(URL(entity_id), http_session)
    ).get("metadata", None)
    if not metadata:
        raise InternalException("No metadata found in entity configuration.")
    if verify:
        Metadata(**metadata).verify()
    return metadata


async def get_entity_jwks(http_session: aiohttp.ClientSession, entity_id: str) -> dict:
    """Fetches the federation JWKS of a given entity ID.

    :param entity_id: The entity ID to fetch the JWKS from (URL).
    :return: The decoded JWKS as a dictionary.
    """
    jwks = utils.get_payload(
        await utils.get_self_signed_entity_configuration(URL(entity_id), http_session)
    ).get("jwks")
    if not jwks:
        raise InternalException("No jwks found in entity configuration.")
    return jwks


async def get_trustchains(
    http_session: aiohttp.ClientSession,
    entity_id: str,
    trust_anchors: List[str] = [],
    export_graph: bool = False,
) -> Tuple[List[trustchain.TrustChain], Optional[pygraphviz.AGraph]]:
    """Builds all trustchains for a given entity ID.

    :param entity_id: The entity ID to build the trustchains for (URL).
    :param trust_anchors: The trust anchor to use for building the trustchains. If not set (empty list), all possible trust chains until the root are built.
    :param export_graph: Whether to export the trustchains as a graph. Defaults to False.
    :return: A tuple containing the trustchains as a list of lists of entity IDs, and the graph representation of the trustchains.
    """
    resolver = trustchain.TrustChainResolver(
        starting_entity=URL(entity_id),
        trust_anchors=[URL(ta) for ta in trust_anchors],
        http_session=http_session,
    )
    await resolver.resolve()
    graph = None
    if export_graph:
        graph = resolver.to_graph()
    return resolver.chains(), graph


async def fetch_entity_statement(
    http_session: aiohttp.ClientSession, entity_id: str, issuer: str
) -> dict:
    return utils.get_payload(
        await utils.fetch_entity_statement(URL(entity_id), URL(issuer), http_session)
    )


async def list_subordinates(
    http_session: aiohttp.ClientSession,
    entity_id: str,
    entity_type: Optional[str] = None,
    trust_marked: bool = False,
    trust_mark_id: Optional[str] = None,
) -> List[str]:
    entity = EntityStatement(
        **utils.get_payload(
            await utils.get_self_signed_entity_configuration(
                URL(entity_id), http_session
            )
        )
    )
    return await utils.get_subordinates(
        http_session, entity, entity_type, trust_marked, trust_mark_id
    )


async def discover(
    http_session: aiohttp.ClientSession, entity_id: str, tas: List[str] = []
) -> List[str]:
    """Discovers all OPs available in the federation to a given RP.

    :param entity_id: The entity ID to discover the OPs for (URL).
    :param tas: The trust anchors to use for discovery. Defaults to [].
    :return: The discovered OPs.
    """
    metadata = await get_entity_metadata(http_session=http_session, entity_id=entity_id)
    # check if it is an openid_relying_party
    if not metadata.get("openid_relying_party"):
        raise InternalException("Entity is not an OpenID Relying Party.")
    # if no trust anchors are given, infer them from building the trustchains
    trust_anchors = []
    if len(tas) == 0:
        resolver = trustchain.TrustChainResolver(
            starting_entity=URL(entity_id), trust_anchors=[], http_session=http_session
        )
        await resolver.resolve()
        chains = resolver.chains()
        if len(chains) == 0:
            raise InternalException("Could not find any trust anchors.")
        for chain in chains:
            trust_anchors.append(chain.get_trust_anchor())
        # filter duplicates
        trust_anchors = list(set(trust_anchors))
    else:
        trust_anchors = [URL(ta) for ta in tas]
    op_list = await fedtree.discover_ops(
        trust_anchors=trust_anchors, http_session=http_session
    )
    return op_list


async def subtree(
    http_session: aiohttp.ClientSession, entity_id: str, export_graph: bool = False
) -> Tuple[dict, Optional[pygraphviz.AGraph]]:
    """Builds the entire federation subtree for given entity_id as root.

    :param entity_id: The entity ID to use as root for the subtree (URL)
    :param export_graph: Whether to export the subtree as a graph. Defaults to False.
    :return: The subtree serialized as a dict.
    """
    subtree = fedtree.FedTree(
        await utils.get_self_signed_entity_configuration(
            entity_id=URL(entity_id), http_session=http_session
        )
    )
    await subtree.discover(http_session)
    graph = None
    if export_graph:
        graph = subtree.to_graph()
    return subtree.serialize(), graph


async def resolve_entity(
    entity_id: str, ta: str, entity_type: str, http_session: aiohttp.ClientSession
) -> dict:
    """Resolves an entity ID's metadata given a trust anchor.

    :param entity_id: The entity ID to resolve (URL).
    :param ta: The trust anchor to use for resolving the entity ID.
    :param entity_type: The entity type to resolve.
    :return: The resolved metadata.
    """
    resolver = trustchain.TrustChainResolver(
        starting_entity=URL(entity_id),
        trust_anchors=[URL(ta)],
        http_session=http_session,
    )
    await resolver.resolve()
    chains = resolver.chains()
    if len(chains) == 0:
        raise InternalException("Could not build trustchain to trust anchor.")
    # TODO: select the shortest chain if more than one
    return chains[0].get_metadata(entity_type)

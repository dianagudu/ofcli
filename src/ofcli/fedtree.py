import pygraphviz
import aiohttp
from typing import List

from ofcli.logging import logger
from ofcli.exceptions import InternalException
from ofcli.utils import (
    EntityStatementPlus,
    URL,
    add_edge_to_graph,
    get_self_signed_entity_configuration,
    get_subordinates,
    get_entity_type,
    add_node_to_graph,
)


class FedTree:
    entity: EntityStatementPlus
    subordinates: List["FedTree"]

    def __init__(self, jwt: str) -> None:
        self.entity = EntityStatementPlus(jwt)
        logger.debug(f"Created tree node for {self.entity.get('sub')}")
        self.subordinates = []

    async def discover(self, http_session: aiohttp.ClientSession) -> None:
        # probably should also verify things here
        if not self.entity.get("metadata"):
            raise InternalException("No metadata found in entity configuration.")
        try:
            subordinates = await get_subordinates(http_session, self.entity)
            for sub in subordinates:
                try:
                    subordinate = FedTree(
                        await get_self_signed_entity_configuration(
                            entity_id=URL(sub), http_session=http_session
                        )
                    )
                    if subordinate.entity.get("sub") == self.entity.get("sub"):
                        raise InternalException(
                            f"Entity is listed as its own subordinate."
                        )
                    await subordinate.discover(http_session)
                    # logger.debug(f"Adding subordinate {subordinate.entity.get('sub')}")
                    # logger.debug(f"{subordinate.entity}")
                    self.subordinates.append(subordinate)
                except Exception as e:
                    logger.warning(f"Could not fetch subordinate {sub}: {e}")
        except Exception as e:
            logger.debug("Could not fetch subordinates, likely a leaf entity: %s" % e)

    def serialize(self) -> dict:
        subordinates = {}
        for sub in self.subordinates:
            subordinates.update(sub.serialize())
        subtree = {
            "entity_type": get_entity_type(self.entity),
            "entity_configuration": self.entity.get_jwt(),
        }
        if len(subordinates) > 0:
            subtree.update({"subordinates": subordinates})  # type: ignore
        return {self.entity.get("sub"): subtree}

    def get_entities(self, entity_type: str) -> List[str]:
        entities = []
        md = self.entity.get("metadata")
        if md and md.get(entity_type):
            entities.append(self.entity.get("sub"))
        for sub in self.subordinates:
            entities += sub.get_entities(entity_type)
        return entities

    def _to_graph(self, graph: pygraphviz.AGraph) -> None:
        logger.debug(f"Adding node for {self.entity.get('sub')}")
        add_node_to_graph(
            graph, self.entity, len(self.entity.get("authority_hints", [])) > 0
        )
        for sub in self.subordinates:
            logger.debug(f"Processing subgraph for {sub.entity.get('sub')}")
            sub._to_graph(graph)
            logger.debug(
                f"Adding edge for {self.entity.get('sub')} -> {sub.entity.get('sub')}"
            )
            add_edge_to_graph(graph, self.entity, sub.entity)

    def to_graph(self) -> pygraphviz.AGraph:
        graph = pygraphviz.AGraph(
            name=f"Subfederation for {self.entity.get('sub')}", directed=True
        )
        self._to_graph(graph)
        return graph


async def discover_ops(
    trust_anchors: List[URL], http_session: aiohttp.ClientSession
) -> List[str]:
    """Discovers all OPs in the federations of the given trust anchors.

    :param trust_anchors: The trust anchors to use.
    :return: A list of OP entity IDs.
    """
    ops = []
    for ta in trust_anchors:
        subtree = FedTree(
            await get_self_signed_entity_configuration(
                entity_id=ta, http_session=http_session
            )
        )
        await subtree.discover(http_session)
        ops += subtree.get_entities("openid_provider")
    # TODO: return OPs as EntityStatements, including the corresponding TA, and apply metadata policies
    return ops

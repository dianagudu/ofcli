import pygraphviz

from ofcli.logging import logger
from ofcli.utils import (
    EntityStatementPlus,
    URL,
    get_self_signed_entity_configuration,
    get_subordinates,
    get_entity_type,
    add_node_to_graph,
)


class FedTree:
    entity: EntityStatementPlus
    subordinates: list["FedTree"]

    def __init__(self, jwt: str) -> None:
        self.entity = EntityStatementPlus(jwt)
        logger.debug(f"Created tree node for {self.entity.get('sub')}")
        self.subordinates = []

    def discover(self) -> None:
        # probably should also verify things here
        if not self.entity.get("metadata"):
            raise Exception("No metadata found in entity configuration.")
        try:
            subordinates = get_subordinates(self.entity)
            for sub in subordinates:
                subordinate = FedTree(get_self_signed_entity_configuration(URL(sub)))
                subordinate.discover()
                self.subordinates.append(subordinate)
        except Exception as e:
            logger.debug("Could not fetch subordinates, likely a leaf entity: %s" % e)

    def serialize(self) -> dict:
        subordinates = {}
        for sub in self.subordinates:
            subordinates.update(sub.serialize())
        subtree = {
            "entity_type": get_entity_type(self.entity),
            "entity_configuration": self.entity.jwt,
        }
        if len(subordinates) > 0:
            subtree.update({"subordinates": subordinates})  # type: ignore
        return {self.entity.get("sub"): subtree}

    def get_entities(self, entity_type: str) -> list[str]:
        entities = []
        md = self.entity.get("metadata")
        if md and md.get(entity_type):
            entities.append(self.entity.get("sub"))
        for sub in self.subordinates:
            entities += sub.get_entities(entity_type)
        return entities

    def _to_graph(self, graph: pygraphviz.AGraph) -> None:
        add_node_to_graph(
            graph, self.entity, len(self.entity.get("authority_hints", [])) > 0
        )
        for sub in self.subordinates:
            sub._to_graph(graph)
            graph.add_edge(self.entity.get("sub"), sub.entity.get("sub"))

    def to_graph(self) -> pygraphviz.AGraph:
        graph = pygraphviz.AGraph(
            name=f"Subfederation for {self.entity.get('sub')}", directed=True
        )
        self._to_graph(graph)
        return graph


def discover_ops(trust_anchors: list[URL]) -> list[str]:
    """Discovers all OPs in the federations of the given trust anchors.

    :param trust_anchors: The trust anchors to use.
    :return: A list of OP entity IDs.
    """
    ops = []
    for ta in trust_anchors:
        subtree = FedTree(get_self_signed_entity_configuration(ta))
        subtree.discover()
        ops += subtree.get_entities("openid_provider")
    # TODO: return OPs as EntityStatements, including the corresponding TA, and apply metadata policies
    return ops

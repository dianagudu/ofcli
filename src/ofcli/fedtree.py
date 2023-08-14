import pygraphviz

from ofcli.logging import logger
from ofcli.message import EntityStatement
from ofcli import utils


class FedTree:
    entity: EntityStatement
    subordinates: list["FedTree"]

    def __init__(self, entity: EntityStatement) -> None:
        self.entity = entity
        self.subordinates = []

    def discover(self) -> None:
        # probably should also verify things here
        logger.debug("Discovering subordinates of %s" % self.entity.get("sub"))
        if not self.entity.get("metadata"):
            raise Exception("No metadata found in entity configuration.")
        try:
            subordinates = utils.get_subordinates(self.entity)
            for sub in subordinates:
                subordinate = FedTree(
                    EntityStatement(**utils.get_self_signed_entity_configuration(sub))
                )
                subordinate.discover()
                self.subordinates.append(subordinate)
        except Exception as e:
            logger.debug("Could not fetch subordinates, likely a leaf entity: %s" % e)

    def serialize(self) -> dict:
        subordinates = {}
        for sub in self.subordinates:
            subordinates.update(sub.serialize())
        subtree = {"entity_type": utils.get_entity_type(self.entity)}
        if len(subordinates) > 0:
            subtree.update({"subordinates": subordinates})
        return {self.entity.get("sub"): subtree}

    def get_entities(self, entity_type: str) -> list[str]:
        entities = []
        md = self.entity.get("metadata")
        if md and md.get(entity_type):
            entities.append(self.entity.get("sub"))
        for sub in self.subordinates:
            entities += sub.get_entities(entity_type)
        return entities

    def _export(self, graph: pygraphviz.AGraph) -> None:
        utils.add_node_to_graph(
            graph, self.entity, len(self.entity.get("authority_hints", [])) > 0
        )
        for sub in self.subordinates:
            sub._export(graph)
            graph.add_edge(self.entity.get("sub"), sub.entity.get("sub"))

    def export(self, filename: str) -> None:
        graph = pygraphviz.AGraph(
            name=f"Subfederation for {self.entity.get('sub')}", directed=True
        )
        self._export(graph)
        graph.write(filename)


def discover_ops(trust_anchors: list[EntityStatement]) -> list[str]:
    """Discovers all OPs in the federations of the given trust anchors.

    :param trust_anchors: The trust anchors to use.
    :return: A list of OP entity IDs.
    """
    ops = []
    for ta in trust_anchors:
        subtree = FedTree(ta)
        subtree.discover()
        ops += subtree.get_entities("openid_provider")
    return ops


def discover(trust_anchor: EntityStatement, export: str | None) -> dict:
    subtree = FedTree(trust_anchor)
    subtree.discover()
    if export:
        subtree.export(export)
    return subtree.serialize()

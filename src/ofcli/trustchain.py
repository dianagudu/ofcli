import datetime
from functools import reduce
import pygraphviz
import click

from ofcli.message import Metadata
from ofcli.utils import (
    URL,
    EntityStatementPlus,
    fetch_entity_statement,
    add_node_to_graph,
    print_json,
)
from ofcli.logging import logger
from ofcli.policy import gather_policies, apply_policy


class TrustChain:
    _chain: list[EntityStatementPlus]
    _exp: int
    _combined_policy: dict[str, dict]
    _metadata: dict[str, dict]

    def __init__(self, chain: list[EntityStatementPlus]) -> None:
        self._chain = chain
        # calculate expiration as the minimum of all entities' expirations
        self._exp = reduce(
            lambda x, y: x if x and x < y.get("exp", 0) else y.get("exp", 0),
            self._chain,
            0,
        )
        if len(self._chain) == 0:
            return
        self._combined_policy = {}
        self._metadata = {}
        for entity_type in self._chain[0].get("metadata", {}).keys():
            if not self._chain[0].get("metadata", {}).get(entity_type):
                continue
            self._combined_policy[entity_type] = gather_policies(
                self._chain, entity_type
            )
            self._metadata[entity_type] = apply_policy(
                self._chain[0].get("metadata", {})[entity_type], self._combined_policy
            )
            logger.debug(
                f"Combined policy for {entity_type}: {self._combined_policy[entity_type]}"
            )
            logger.debug(
                f"Metadata for {entity_type} after applying policies: {self._metadata[entity_type]}"
            )

    def __str__(self) -> str:
        """Prints the entity IDs in the chain. The last one is the trust anchor."""
        return (
            " -> ".join([link.get("iss") or "" for link in self._chain[:-1]])
            + " (expiring at "
            + datetime.datetime.fromtimestamp(self._exp).isoformat()
            + ")"
        )

    def to_json(self) -> dict:
        return {
            "chain": [
                {
                    "iss": link.get("iss"),
                    "sub": link.get("sub"),
                    "entity_statement": link.jwt,
                }
                for link in self._chain
            ],
            "exp": datetime.datetime.fromtimestamp(self._exp).isoformat(),
        }

    def get_trust_anchor(self) -> URL:
        # return last link in chain
        if len(self._chain) == 0:
            raise Exception("Malformed chain. No trust anchor found.")
        return URL(self._chain[-1].entity_id)

    def get_metadata(self, entity_type: str) -> dict:
        md = self._metadata.get(entity_type)
        if not md:
            raise Exception(f"No metadata found for entity type {entity_type}")
        return Metadata(**md).to_dict()

    def get_combined_policy(self) -> dict:
        return self._combined_policy


class TrustTree:
    entity: EntityStatementPlus
    subordinate: EntityStatementPlus | None
    authorities: list["TrustTree"]

    def __init__(
        self, entity: EntityStatementPlus, subordinate: EntityStatementPlus | None
    ) -> None:
        self.entity = entity
        self.subordinate = subordinate
        self.authorities = []

    def resolve(self, anchors: list[URL], seen: list[URL] = []) -> bool:
        """Recursively resolve the trust tree.
        If no trust anchor is found, build the trust tree for all anchors.

        Args:
            anchors (list[URL]): List of trust anchors.
            seen (list[URL], optional): List of already seen entities (to avoid loops). Defaults to [].

        Returns:
            bool: True if the trust tree is valid, False otherwise.
        """
        logger.debug(f"Resolving {self.entity.get('sub')}")
        sub = self.entity.get("sub")
        if not sub:
            raise Exception("No sub found in entity statement.")
        sub = URL(sub)
        seen.append(sub)
        logger.debug(f"Seen: {seen}")
        if sub in anchors:
            logger.debug(f"Found trust anchor {sub}")
            return True
        logger.debug(
            f"Evaluating authority hints: {self.entity.get('authority_hints')}"
        )
        if len(self.entity.get("authority_hints", [])) == 0:
            if len(anchors) == 0:
                logger.debug(f"No trust anchor given, resolving all trust trees.")
                return True
            else:
                logger.debug(f"Unknown trust anchor: {sub}")
                return False
        valid = False
        for authority in self.entity.get("authority_hints", []):
            logger.debug(f"Fetching self signed entity statement for {authority}")
            authority = URL(authority)
            authority_statement = EntityStatementPlus.fetch(authority)
            logger.debug(f"Fetching entity statement for {sub} from {authority}")
            try:
                subordinate_statement = EntityStatementPlus(
                    fetch_entity_statement(sub, authority)
                )
            except Exception as e:
                logger.debug(e)
                return False
            tt = TrustTree(
                authority_statement,
                subordinate_statement,
            )
            if tt.resolve(anchors, seen):
                valid = True
                self.authorities.append(tt)
        return valid

    def verify_signatures(self, anchors: list[URL]) -> bool:
        # TODO: verify signatures
        return True

    def chains(self) -> list[list[EntityStatementPlus]]:
        """Serializes trust chains from trust tree.

        Returns:
            list[list[EntityStatementPlus]]: List of trust chains.
        """
        if len(self.authorities) == 0:
            if self.subordinate is None:
                return []
            return [[self.subordinate, self.entity]]
        chains = []
        for authority in self.authorities:
            if self.subordinate is None:
                chains += authority.chains()
                continue
            for chain in authority.chains():
                chain = [self.subordinate] + chain
                chains = [chain] + chains
        return chains


class TrustChainResolver:
    starting_entity: URL
    trust_anchors: list[URL]
    trust_tree: TrustTree | None = None

    def __init__(self, starting_entity: URL, trust_anchors: list[URL]) -> None:
        self.starting_entity = starting_entity
        self.trust_anchors = trust_anchors

    def resolve(self) -> None:
        starting = EntityStatementPlus.fetch(self.starting_entity)
        self.trust_tree = TrustTree(starting, None)
        self.trust_tree.resolve(self.trust_anchors)

    def to_graph(self) -> pygraphviz.AGraph | None:
        if self.trust_tree:
            graph = pygraphviz.AGraph(
                name=f"Trustchains: {self.starting_entity}", directed=True
            )
            self._to_graph(self.trust_tree, graph)
            return graph
        return None

    def _to_graph(self, trust_tree: TrustTree, graph: pygraphviz.AGraph) -> None:
        add_node_to_graph(graph, trust_tree.entity, len(trust_tree.authorities) == 0)
        if trust_tree.subordinate:
            graph.add_edge(
                trust_tree.entity.get("sub"), trust_tree.subordinate.get("sub")
            )
        for authority in trust_tree.authorities:
            self._to_graph(authority, graph)

    def chains(self) -> list[TrustChain]:
        if self.trust_tree:
            chains = self.trust_tree.chains()
            logger.debug(f"Found {len(chains)} trust chains.")
            for i, chain in enumerate(chains):
                chains[i] = [self.trust_tree.entity] + chain
            return [TrustChain(chain) for chain in chains]
        return []

    def verify_signatures(self) -> bool:
        if self.trust_tree:
            return self.trust_tree.verify_signatures(self.trust_anchors)
        return False


def print_trustchains(chains: list[TrustChain], details: bool):
    if len(chains) == 0:
        logger.warn("No trust chains found.")
        return
    if details:
        for chain in chains:
            print_json(chain.to_json())
    else:
        for chain in chains:
            click.echo("* " + str(chain))

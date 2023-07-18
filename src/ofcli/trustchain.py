import datetime
from functools import reduce
import pygraphviz

from ofcli.message import EntityStatement
from ofcli import utils
from ofcli.logging import logger


class TrustChain:
    _chain: list[EntityStatement]
    _exp: int

    def __init__(self, chain: list[EntityStatement]) -> None:
        self._chain = chain
        # calculate expiration as the minimum of all entities' expirations
        self._exp = reduce(
            lambda x, y: x if x and x < y.get("exp", 0) else y.get("exp", 0),
            self._chain,
            0,
        )

    def __str__(self) -> str:
        return (
            "* "
            + " -> ".join([link.get("iss") or "" for link in self._chain])
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
                    "entity_statement": link.to_jwt(),
                }
                for link in self._chain
            ],
            "exp": datetime.datetime.fromtimestamp(self._exp).isoformat(),
        }

    def combined_metadata_policy(self) -> dict:
        pass

    def apply_policy(self) -> dict:
        pass


class TrustTree:
    entity: EntityStatement
    subordinate: EntityStatement | None
    authorities: list["TrustTree"]

    def __init__(
        self, entity: EntityStatement, subordinate: EntityStatement | None
    ) -> None:
        self.entity = entity
        self.subordinate = subordinate
        self.authorities = []

    def resolve(self, anchors: list[str], seen: list[str] = []) -> bool:
        """Recursively resolve the trust tree.
        If no trust anchor is found, build the trust tree for all anchors.

        Args:
            anchors (list[str]): List of trust anchors.
            seen (list[str], optional): List of already seen entities (to avoid loops). Defaults to [].

        Returns:
            bool: True if the trust tree is valid, False otherwise.
        """
        logger.debug(f"Resolving {self.entity.get('sub')}")
        sub = self.entity.get("sub")
        if not sub:
            raise Exception("No sub found in entity statement.")
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
            authority_statement = EntityStatement(
                **utils.get_self_signed_entity_configuration(authority)
            )
            logger.debug(f"Fetching entity statement for {sub} from {authority}")
            subordinate_statement = EntityStatement(
                **utils.fetch_entity_statement(sub, authority)
            )
            tt = TrustTree(
                authority_statement,
                subordinate_statement,
            )
            if tt.resolve(anchors, seen):
                valid = True
                self.authorities.append(tt)
        return valid

    def verify_signatures(self, anchors: list[str]) -> bool:
        # TODO: verify signatures
        return True

    def chains(self) -> list[list[EntityStatement]]:
        """Serializes trust chains from trust tree.

        Returns:
            list[list[EntityStatement]]: List of trust chains.
        """
        if len(self.authorities) == 0:
            if self.subordinate is None:
                return []
            return [[self.subordinate]]
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
    starting_entity: str
    trust_anchors: list[str]
    trust_tree: TrustTree | None = None

    def __init__(self, starting_entity: str, trust_anchors: list[str]) -> None:
        self.starting_entity = starting_entity
        self.trust_anchors = trust_anchors

    def resolve(self) -> None:
        starting = EntityStatement(
            **utils.get_self_signed_entity_configuration(self.starting_entity)
        )
        self.trust_tree = TrustTree(starting, None)
        self.trust_tree.resolve(self.trust_anchors)

    def export(self, filename: str) -> None:
        if self.trust_tree:
            graph = pygraphviz.AGraph(
                name=f"Trustchains: {self.starting_entity}", directed=True
            )
            self._export(self.trust_tree, graph)
            graph.write(filename)

    def _export(self, trust_tree: TrustTree, graph: pygraphviz.AGraph) -> None:
        if trust_tree.subordinate:
            graph.add_edge(
                trust_tree.entity.get("sub"), trust_tree.subordinate.get("sub")
            )
        for authority in trust_tree.authorities:
            self._export(authority, graph)

    def chains(self) -> list[TrustChain]:
        if self.trust_tree:
            chains = self.trust_tree.chains()
            for i, chain in enumerate(chains):
                chains[i] = [self.trust_tree.entity] + chain
            return [TrustChain(chain) for chain in chains]
        return []

    def verify_signatures(self) -> bool:
        if self.trust_tree:
            return self.trust_tree.verify_signatures(self.trust_anchors)
        return False

    def apply_policy(self) -> dict:
        if self.trust_tree:
            return self._apply_policy(self.trust_tree)
        return {}

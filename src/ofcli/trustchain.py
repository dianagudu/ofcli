from functools import reduce
import pygraphviz

from ofcli.message import EntityStatement
from ofcli import utils


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
            #     + " (expiring at "
            #     + str(self._exp)
            #     + ")"
        )

    def contains_trust_anchors(self, trust_anchors: list[str]) -> bool:
        if len(trust_anchors) == 0:
            return True
        trusted = False
        for entity in self._chain:
            if entity.get("iss") in trust_anchors:
                trusted = True
                break
        return trusted


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

    def resolve(self, anchors: list[str]) -> None:
        issuer = self.entity.get("iss")
        if not issuer:
            raise Exception("No issuer found in entity statement.")
        if issuer in anchors:
            return
        for authority in self.entity.get("authority_hints", []):
            authority_statement = EntityStatement(
                **utils.get_self_signed_entity_configuration(authority)
            )
            subordinate_statement = EntityStatement(
                **utils.fetch_entity_statement(issuer, authority)
            )
            tt = TrustTree(
                authority_statement,
                subordinate_statement,
            )
            tt.resolve(anchors)
            self.authorities.append(tt)

    def verify_signatures(self, anchors: list[str]) -> bool:
        return True

    def chains(self) -> list[list[EntityStatement]]:
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

    def _export(self, trust_tree: TrustTree, graph: pygraphviz.AGraph) -> None:
        if trust_tree.subordinate:
            graph.add_edge(
                trust_tree.entity.get("sub"), trust_tree.subordinate.get("sub")
            )
        for authority in trust_tree.authorities:
            self._export(authority, graph)

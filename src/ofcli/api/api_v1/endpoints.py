from fastapi import Request
from fastapi.params import Query, Path
from fastapi.responses import JSONResponse, PlainTextResponse, Response

# for python 3.8, import Annotated from typing_extensions
import sys

if sys.version_info >= (3, 9):
    from typing import Annotated
else:
    from typing_extensions import Annotated
from typing import Optional, List, Dict
from pydantic import HttpUrl
import aiohttp

from ofcli import __version__
from ofcli import core
from ofcli.utils import (
    APIRouter,
    EntityType,
    OutputType,
    subtree_to_string,
)
from ofcli.exceptions import (
    InternalException,
)

router = APIRouter()


@router.get(path="/", name="index", description="Retrieve general API information.")
async def index(request: Request) -> List[Dict[str, str]]:
    def get_route_info(route):
        info = {
            "path": route.path,
            "name": route.name,
        }
        if hasattr(route, "summary") and route.summary:
            info["summary"] = route.summary
        if hasattr(route, "description") and route.description:
            info["description"] = route.description
        return info

    url_list = [
        get_route_info(route)
        for route in request.app.routes
        if route.include_in_schema and route.path.startswith(request.url.path)
    ]
    return url_list


@router.get(
    path="/entity/{entity_id:path}",
    name="entity",
    description="Returns the decoded self-signed entity configuration for given entity_id.",
)
async def entity(
    entity_id: Annotated[
        HttpUrl,
        Path(
            description="Entity ID",
        ),
    ],
    verify: Annotated[
        bool,
        Query(description="Whether to verify the entity configuration's signature"),
    ] = False,
):
    configuration = await core.get_entity_configuration(
        entity_id=entity_id.unicode_string(),
        verify=verify,
        http_session=aiohttp.ClientSession(),
    )
    return configuration


@router.get(path="/fetch", name="fetch", description="Fetches an entity statement.")
async def fetch(
    entity_id: Annotated[
        HttpUrl,
        Query(
            description="Entity ID",
        ),
    ],
    issuer: Annotated[
        HttpUrl,
        Query(
            description="Issuer ID",
        ),
    ],
):
    statement = await core.fetch_entity_statement(
        entity_id=entity_id.unicode_string(),
        issuer=issuer.unicode_string(),
        http_session=aiohttp.ClientSession(),
    )
    return statement


@router.get(
    path="/list/{entity_id:path}",
    name="list",
    description="Lists all subordinates of an entity.",
)
async def list_subordinates(
    entity_id: Annotated[
        HttpUrl,
        Path(
            description="Entity ID",
        ),
    ],
    entity_type: Annotated[
        Optional[EntityType],
        Query(
            description="Entity type to filter for.",
        ),
    ] = None,
):
    subordinates = await core.list_subordinates(
        entity_id=entity_id.unicode_string(),
        entity_type=entity_type.value if entity_type else None,
        http_session=aiohttp.ClientSession(),
    )
    return subordinates


@router.get(
    path="/trustchains/{entity_id:path}",
    name="trustchains",
    description="Builds all trustchains for a given entity and prints them. If any trust anchor is specified, only trustchains ending in the trust anchor will be returned.",
)
async def trustchains(
    entity_id: Annotated[
        HttpUrl,
        Path(
            description="Entity ID to build trustchains for.",
        ),
    ],
    ta: Annotated[
        List[HttpUrl],
        Query(
            description="Trust anchor ID to use for building trustchains (multiple TAs possible)."
        ),
    ] = [],
    format: OutputType = OutputType.json,
):
    chains, graph = await core.get_trustchains(
        entity_id=entity_id.unicode_string(),
        trust_anchors=[ta_item.unicode_string() for ta_item in ta],
        export_graph=format == OutputType.dot,
        http_session=aiohttp.ClientSession(),
    )
    if format == OutputType.dot:
        if not graph:
            raise InternalException("No graph to export.")
        return Response(graph.to_string(), media_type="file/dot")
    if format == OutputType.text:
        response = ""
        for chain in chains:
            response += "* " + (str(chain)) + "\n"
        return PlainTextResponse(response)
    # if format == OutputType.json:
    response = {}
    for i, chain in enumerate(chains):
        response[f"chain {i}"] = chain.to_json()
    return JSONResponse(response)


@router.get(
    path="/subtree/{entity_id:path}",
    name="subtree",
    description="Discover federation subtree using given entity as root.",
)
async def subtree(
    entity_id: Annotated[
        HttpUrl,
        Path(
            description="Entity ID to use as root for federation subtree.",
        ),
    ],
    format: OutputType = OutputType.json,
):
    tree, graph = await core.subtree(
        entity_id=entity_id.unicode_string(),
        export_graph=format == OutputType.dot,
        http_session=aiohttp.ClientSession(),
    )
    if format == OutputType.dot:
        if not graph:
            raise InternalException("No graph to export.")
        return Response(graph.to_string(), media_type="file/dot")
    if format == OutputType.text:
        return PlainTextResponse(subtree_to_string(tree))
    # if format == OutputType.json:
    return JSONResponse(tree)


@router.get(
    path="/resolve/{entity_id:path}",
    name="resolve",
    description="Resolve metadata and Trust Marks for an entity, given a trust anchor and entity type.",
)
async def resolve(
    entity_id: Annotated[
        HttpUrl,
        Path(
            description="Entity ID to resolve.",
        ),
    ],
    ta: Annotated[HttpUrl, Query(description="Trust anchor ID to use for resolving.")],
    entity_type: Annotated[EntityType, Query()],
):
    metadata = await core.resolve_entity(
        entity_id=entity_id.unicode_string(),
        ta=ta.unicode_string(),
        entity_type=entity_type.value,
        http_session=aiohttp.ClientSession(),
    )
    return metadata


@router.get(
    path="/discovery/{entity_id:path}",
    name="discovery",
    description="Discover all OPs in the federation available to a given RP. If no trust anchor is specified, all possible trust anchors will be used.",
)
async def discovery(
    entity_id: Annotated[
        HttpUrl,
        Path(
            description="Relying Party ID.",
        ),
    ],
    ta: Annotated[
        List[HttpUrl],
        Query(
            description="Trust anchor ID to use for OP discovery (multiple TAs possible)."
        ),
    ] = [],
):
    ops = await core.discover(
        entity_id=entity_id.unicode_string(),
        tas=[ta_item.unicode_string() for ta_item in ta],
        http_session=aiohttp.ClientSession(),
    )
    return ops

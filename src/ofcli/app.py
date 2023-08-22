from fastapi import FastAPI, Request
from fastapi.params import Query, Path
from fastapi.responses import JSONResponse, PlainTextResponse, Response
import uvicorn
from typing import Annotated, Optional
from pydantic import HttpUrl

from ofcli import utils, api

app = FastAPI()


@app.get(path="/", name="index", description="Retrieve general API information.")
async def index(request: Request) -> list[dict[str, str]]:
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

    url_list = [get_route_info(route) for route in request.app.routes]
    return url_list


@app.get(
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
        list[HttpUrl],
        Query(
            description="Trust anchor ID to use for building trustchains (multiple TAs possible)."
        ),
    ] = [],
    format: utils.OutputType = utils.OutputType.json,
):
    chains, graph = api.get_trustchains(
        entity_id.unicode_string(),
        [ta_item.unicode_string() for ta_item in ta],
        format == utils.OutputType.dot,
    )
    if format == utils.OutputType.dot:
        if not graph:
            raise Exception("No graph to export.")
        return Response(graph.to_string(), media_type="file/dot")
    if format == utils.OutputType.text:
        response = ""
        for chain in chains:
            response += "* " + (str(chain)) + "\n"
        return PlainTextResponse(response)
    # if format == utils.OutputType.json:
    response = {}
    for i, chain in enumerate(chains):
        response[f"chain {i}"] = chain.to_json()
    return JSONResponse(response)


@app.get(
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
    format: utils.OutputType = utils.OutputType.json,
):
    tree, graph = api.subtree(
        entity_id.unicode_string(), format == utils.OutputType.dot
    )
    if format == utils.OutputType.dot:
        if not graph:
            raise Exception("No graph to export.")
        return Response(graph.to_string(), media_type="file/dot")
    if format == utils.OutputType.text:
        return PlainTextResponse(utils.subtree_to_string(tree))
    # if format == utils.OutputType.json:
    return JSONResponse(tree)


@app.get(
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
    entity_type: Annotated[utils.EntityType, Query()],
):
    metadata = api.resolve_entity(
        entity_id.unicode_string(), ta.unicode_string(), entity_type.value
    )
    return metadata


@app.get(
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
        list[HttpUrl],
        Query(
            description="Trust anchor ID to use for OP discovery (multiple TAs possible)."
        ),
    ] = [],
):
    ops = api.discover(
        entity_id.unicode_string(), [ta_item.unicode_string() for ta_item in ta]
    )
    return ops


@app.get(
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
    configuration = api.get_entity_configuration(
        entity_id.unicode_string(), verify=verify
    )
    return configuration


@app.get(path="/fetch", name="fetch", description="Fetches an entity statement.")
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
    statement = api.fetch_entity_statement(
        entity_id.unicode_string(), issuer.unicode_string()
    )
    return statement


@app.get(
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
        Optional[utils.EntityType],
        Query(
            description="Entity type to filter for.",
        ),
    ] = None,
):
    subordinates = api.list_subordinates(
        entity_id.unicode_string(),
        entity_type=entity_type.value if entity_type else None,
    )
    return subordinates


def main():
    uvicorn.run("ofcli.app:app", host="0.0.0.0", port=12345, log_level="info")

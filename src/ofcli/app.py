from fastapi import FastAPI, Request
from fastapi.params import Query
from fastapi.responses import JSONResponse, PlainTextResponse, Response
import uvicorn
from typing import Annotated
from pydantic import HttpUrl

from ofcli import utils, api

app = FastAPI()


@app.get(path="/", name="index")
def index(request: Request) -> list[dict[str, str]]:
    url_list = [
        {
            "path": route.path,
            "name": route.name,
        }
        for route in request.app.routes
    ]
    return url_list


@app.get(path="/trustchains/{entity_id:path}", name="trustchains")
def trustchains(
    entity_id: str,
    ta: Annotated[list[str], Query()] = [],
    format: utils.OutputType = utils.OutputType.json,
):
    chains, graph = api.get_trustchains(
        entity_id,
        ta,
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


@app.get(path="/subtree/{entity_id:path}", name="subtree")
def subtree(entity_id: str, format: utils.OutputType = utils.OutputType.json):
    tree, graph = api.subtree(entity_id, format == utils.OutputType.dot)
    if format == utils.OutputType.dot:
        if not graph:
            raise Exception("No graph to export.")
        return Response(graph.to_string(), media_type="file/dot")
    if format == utils.OutputType.text:
        return PlainTextResponse(utils.subtree_to_string(tree))
    # if format == utils.OutputType.json:
    return JSONResponse(tree)


@app.get(path="/resolve/{entity_id:path}", name="resolve")
def resolve(
    entity_id: str, ta: Annotated[str, Query()], entity_type: Annotated[str, Query()]
):
    metadata = api.resolve_entity(entity_id, ta, entity_type)
    return metadata


@app.get(path="/discovery/{entity_id:path}", name="discovery")
def discovery(entity_id: str, ta: Annotated[list[str], Query()] = []):
    ops = api.discover(entity_id, ta)
    return ops


def main():
    uvicorn.run("ofcli.app:app", host="0.0.0.0", port=12345, log_level="info")

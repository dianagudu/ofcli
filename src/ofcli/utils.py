"""Utility functions for OIDC Federation CLI."""

import re
import typing as t
from gettext import gettext as _
import json
import urllib.parse
import click
from pydantic import HttpUrl
import pydantic_core
import pygraphviz
import requests
from cryptojwt.jws.jws import factory
import enum

from ofcli.logging import logger
from ofcli import __version__ as ofcli_version, __name__ as ofcli_name
from ofcli.message import EntityStatement

VERIFY_SSL = True


# define colors for different metadata types
class ColorScheme:
    OP = "#01425E"
    RP = "#DD4C1A"
    IA = "#5B317B"
    TA = "#C50679"


COLORS = {
    "openid_relying_party": ColorScheme.RP,
    "openid_provider": ColorScheme.OP,
    "oauth_authorization_server": ColorScheme.OP,
    "oauth_client": ColorScheme.RP,
    "oauth_resource_server": ColorScheme.RP,
    "federation_entity": ColorScheme.TA,
}


class OutputType(str, enum.Enum):
    json = "json"
    dot = "dot"
    text = "text"


class EntityType(str, enum.Enum):
    openid_relying_party = "openid_relying_party"
    openid_provider = "openid_provider"
    oauth_authorization_server = "oauth_authorization_server"
    oauth_client = "oauth_client"
    oauth_resource_server = "oauth_resource_server"
    federation_entity = "federation_entity"


class URL:
    def __init__(self, url: str):
        self._url = HttpUrl(url)
        self._original = url

    def __str__(self):
        return self._url.__str__()

    def __repr__(self):
        return self.__str__()

    def url(self):
        return self._url

    def __eq__(self, other):
        if isinstance(other, URL):
            return self._url == other.url()
        if isinstance(other, str):
            return self._url == HttpUrl(other)
        if isinstance(other, pydantic_core.Url):
            return self._url == other
        return False

    def __hash__(self):
        return hash(self._url)

    def add_query_params(self, params: dict) -> "URL":
        """Adds query parameters to a URL and returns a new URL.
        :param url: The URL to add the query parameters to.
        :param params: The query parameters to add.
        :return: The URL with the query parameters added.
        """
        url_parts = list(urllib.parse.urlparse(str(self)))
        query = dict(urllib.parse.parse_qsl(url_parts[4]))
        query.update(params)
        url_parts[4] = urllib.parse.urlencode(query)
        return URL(urllib.parse.urlunparse(url_parts))

    def remove_trailing_slashes(self) -> str:
        """Removes trailing slashes from a URL and returns the new URL as a string.
        :param url: The URL to remove the trailing slashes from.
        :return: The URL without trailing slashes as a string
        """
        url_parts = list(urllib.parse.urlparse(str(self)))
        url_parts[2] = url_parts[2].rstrip("/")
        return urllib.parse.urlunparse(url_parts)


def set_verify_ssl(ctx, param, value):
    """
    First, take over value from parent, if set.
    Might seem weird: the flag is called --insecure, but the
    meaning of the value is verify:
    - True by default, verify if HTTPS requests are secure, verify certificates
    - False means do not verify, disable warnings.
    When the flag is set, verify will be False.
    """
    try:
        value = ctx.meta[param.name]
    except Exception:
        # set the verify in the context meta dict to be used by subcommands
        # only if it was set through the commandline
        if (
            ctx.get_parameter_source(param.name)
            is click.core.ParameterSource.COMMANDLINE
        ):
            ctx.meta[param.name] = value
    global VERIFY_SSL
    VERIFY_SSL = not value
    # urllib3.disable_warnings()
    return value


def print_version(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    """Print version and exit context."""
    if not value or ctx.resilient_parsing:
        return

    package_name = ofcli_name
    package_version = ofcli_version
    prog_name = ctx.find_root().info_name

    message = _("%(package)s, %(version)s")

    if package_version is None:
        raise RuntimeError(
            f"Could not determine the version for {package_name!r} automatically."
        )

    click.echo(
        t.cast(str, message)
        % {"prog": prog_name, "package": package_name, "version": package_version},
        color=ctx.color,
    )
    ctx.exit()


def well_known_url(entity_id: URL) -> URL:
    """Returns the well-known URL for a given entity ID.

    :param entity_id: The entity ID to get the well-known URL for.
    :return: The well-known URL.
    """
    return URL(str(entity_id).rstrip("/") + "/.well-known/openid-federation")


def fetch_jws_from_url(url: URL) -> str:
    """Fetches a JWS from a given URL.

    :param url: The url to fetch the entity configuration from.
    :return: The JWS as a string.
    """
    response = None
    for tried_url in [url.remove_trailing_slashes(), str(url)]:
        response = requests.request("GET", tried_url, verify=VERIFY_SSL)

        if response.status_code == 200:
            return response.text

    raise ValueError(
        "Could not fetch entity statement from %s. Status code: %s"
        % (url, response.status_code if response is not None else "unknown")
    )


def get_payload(jws_str: str) -> dict:
    """Gets the payload of a JWS.

    :param jws_str: The JWS as a string.
    :return: The payload of the JWS as a dictionary.
    """
    jws = factory(jws_str)
    if not jws:
        raise ValueError("Could not parse entity configuration as JWS.")

    payload = jws.jwt.payload()
    if not payload:
        raise ValueError("Could not parse entity configuration payload.")
    if not isinstance(payload, dict):
        raise ValueError("Entity configuration payload is not a mapping: %s" % payload)

    return payload


def get_self_signed_entity_configuration(entity_id: URL) -> str:
    """Fetches the self-signed entity configuration of a given entity ID.

    :param entity_id: The entity ID to fetch the entity configuration from (URL).
    :return: The entity configuration as a JWT.
    """
    return fetch_jws_from_url(well_known_url(entity_id))


def fetch_entity_statement(entity_id: URL, issuer: URL) -> str:
    issuer_metadata = get_payload(get_self_signed_entity_configuration(issuer)).get(
        "metadata"
    )
    if not issuer_metadata:
        raise Exception("No metadata found in entity configuration.")
    try:
        fe = issuer_metadata["federation_entity"]
    except KeyError:
        raise Exception("Leaf entities cannot publish statements about other entities.")
    try:
        fetch_url = URL(fe["federation_fetch_endpoint"])
    except KeyError:
        raise Exception("No federation_fetch_endpoint found in metadata!")

    last_exception = None
    for entity_id_url in [entity_id.remove_trailing_slashes(), str(entity_id)]:
        for issuer_url in [issuer.remove_trailing_slashes(), str(issuer)]:
            try:
                return fetch_jws_from_url(
                    fetch_url.add_query_params(
                        {"iss": issuer_url, "sub": entity_id_url}
                    )
                )

            except Exception as e:
                last_exception = e
                logger.debug(e)
    raise last_exception if last_exception else Exception("Unknown error")


def get_subordinates(
    entity: EntityStatement,
    entity_type: str | None = None,
    trust_marked: bool = False,
    trust_mark_id: str | None = None,
) -> list[str]:
    metadata = entity.get("metadata")
    if not metadata:
        raise Exception("No metadata found in entity configuration.")
    try:
        le = metadata["federation_entity"]
    except KeyError:
        raise Exception("Leaf entities cannot have subordinates.")
    try:
        list_url = URL(le["federation_list_endpoint"])
    except KeyError:
        raise Exception("No federation_list_endpoint found in metadata!")

    params = {}
    if entity_type:
        params["entity_type"] = entity_type
    if trust_marked:
        params["trust_marked"] = trust_marked
    if trust_mark_id:
        params["trust_mark_id"] = trust_mark_id

    url = list_url.add_query_params(params)
    response = requests.request("GET", str(url), verify=VERIFY_SSL)

    if response.status_code != 200:
        raise ValueError(
            "Could not fetch subordinates from %s. Status code: %s"
            % (url, response.status_code)
        )
    subs = json.loads(response.text)
    if not subs:
        return []
    return list(subs)


def print_json(data: dict | list):
    json.dump(data, click.get_text_stream("stdout"), indent=2)


def _subtree_to_string(entity_id: URL, entity_info: dict, indent: int = 0) -> str:
    prefix = "  " * indent + "- "
    output = f"{prefix}{entity_id} ({entity_info['entity_type']})\n"
    if "subordinates" in entity_info:
        for sub_id, sub_info in entity_info["subordinates"].items():
            output += _subtree_to_string(sub_id, sub_info, indent + 1)
    return output


def subtree_to_string(subtree: dict) -> str:
    output = ""
    for entity_id, entity_info in subtree.items():
        output += _subtree_to_string(entity_id, entity_info)
    return output


def print_subtree(serialized_subtree: dict, details: bool):
    if details:
        print_json(serialized_subtree)
    else:
        click.echo(subtree_to_string(serialized_subtree), nl=False)


def add_node_to_graph(
    graph: pygraphviz.AGraph, entity: EntityStatement, is_ta: bool = False
):
    entity_type = get_entity_type(entity)
    color = COLORS[entity_type]
    if entity_type == "federation_entity" and not is_ta:
        color = ColorScheme.IA
    graph.add_node(
        entity.get("sub"),
        style="filled",
        fillcolor=color,
        fontcolor="white",
        label=f"<{entity.get('sub')} <br /> <font point-size='10'>{entity_type}</font>>",
        URL=entity.get("sub"),
        comment=entity.to_dict(),
    )


def get_entity_type(entity: EntityStatement) -> str:
    # logger.debug(f"Getting metadata type for {entity.get('sub')}")
    md = entity.get("metadata")
    if not md:
        raise Exception("No metadata found in entity statement")
    etypes = list(md.to_dict().keys())
    # logger.debug(f"Found metadata types: {etypes}")
    if len(etypes) == 0:
        raise Exception("Empty metadata")
    if len(etypes) > 1:
        logger.warning(
            "Entity has multiple metadata types, choosing one randomly with priority for non-leaf entities."
        )
        # if "federation_entity" in etypes:
        #     return [t for t in etypes if t != "federation_entity"][0]
    return etypes[0]


class EntityStatementPlus(EntityStatement):
    jwt: str
    entity_id: str

    def __init__(self, jwt: str):
        super().__init__(**get_payload(jwt))
        self.jwt = jwt
        self.entity_id = self.get("sub", "")

    @staticmethod
    def fetch(url: URL) -> "EntityStatementPlus":
        return EntityStatementPlus(get_self_signed_entity_configuration(url))

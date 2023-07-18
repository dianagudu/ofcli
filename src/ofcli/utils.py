"""Utility functions for OIDC Federation CLI."""

import typing as t
from gettext import gettext as _
import json
import urllib.parse
import click
import requests
from cryptojwt.jws.jws import factory

from ofcli import trustchain
from ofcli.logging import logger
from ofcli import __version__ as ofcli_version, __name__ as ofcli_name

VERIFY_SSL = True


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


def well_known_url(entity_id: str) -> str:
    """Returns the well-known URL for a given entity ID.

    :param entity_id: The entity ID to get the well-known URL for.
    :return: The well-known URL.
    """
    return entity_id.rstrip("/") + "/.well-known/openid-federation"


def fetch_jws_from_url(url: str) -> str:
    """Fetches a JWS from a given URL.

    :param url: The url to fetch the entity configuration from.
    :return: The JWS as a string.
    """
    # logger.debug(f"Using insecure connection: {not VERIFY_SSL}")
    response = requests.request("GET", url, verify=VERIFY_SSL)

    if response.status_code != 200:
        raise ValueError(
            "Could not fetch entity statement from %s. Status code: %s"
            % (url, response.status_code)
        )

    return response.text


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


def add_query_params(url: str, params: dict) -> str:
    """Adds query parameters to a URL.

    :param url: The URL to add the query parameters to.
    :param params: The query parameters to add.
    :return: The URL with the query parameters added.
    """
    url_parts = list(urllib.parse.urlparse(url))
    query = dict(urllib.parse.parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(url_parts)


def get_self_signed_entity_configuration(entity_id: str) -> dict:
    """Fetches the self-signed entity configuration of a given entity ID.

    :param entity_id: The entity ID to fetch the entity configuration from (URL).
    :return: The decoded entity configuration as a dictionary.
    """
    return get_payload(fetch_jws_from_url(well_known_url(entity_id)))


def fetch_entity_statement(entity_id: str, issuer: str) -> dict:
    issuer_metadata = get_self_signed_entity_configuration(issuer).get("metadata")
    if not issuer_metadata:
        raise Exception("No metadata found in entity configuration.")
    try:
        fe = issuer_metadata["federation_entity"]
    except KeyError:
        raise Exception("Leaf entities cannot publish statements about other entities.")
    try:
        fetch_url = fe["federation_fetch_endpoint"]
    except KeyError:
        raise Exception("No federation_fetch_endpoint found in metadata!")
    return get_payload(
        fetch_jws_from_url(
            add_query_params(fetch_url, {"iss": issuer, "sub": entity_id})
        )
    )


def build_trustchains(
    entity_id: str, trust_anchors: list[str], export: str | None
) -> list[trustchain.TrustChain]:
    resolver = trustchain.TrustChainResolver(entity_id, trust_anchors)
    resolver.resolve()
    if export:
        resolver.export(export)
    return resolver.chains()


def print_json(data: dict):
    json.dump(data, click.get_text_stream("stdout"), indent=2)


def print_trustchains(chains: list[trustchain.TrustChain], details: bool):
    if len(chains) == 0:
        logger.warn("No trust chains found.")
        return
    if details:
        for chain in chains:
            print_json(chain.to_json())
    else:
        for chain in chains:
            click.echo(chain)


def discover(entity_id: str, trust_anchors: list[str]) -> list[str]:
    return []


# def print_trustchains(trustchain: dict, indent: int = 0):
#     """Prints a trustchain to stdout.

#     :param trustchain: The trustchain to print.
#     :param indent: The indentation level to use. Defaults to 0.
#     """
#     for superior, chain in trustchain.items():
#         click.echo("\t" * indent + superior)
#         print_trustchains(chain, indent + 1)

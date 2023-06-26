"""Utility functions for OIDC Federation CLI."""

import json
import urllib.parse
import click
import requests
from cryptojwt.jws.jws import factory


def well_known_url(entity_id: str) -> str:
    """Returns the well-known URL for a given entity ID.

    :param entity_id: The entity ID to get the well-known URL for.
    :return: The well-known URL.
    """
    return entity_id.rstrip("/") + "/.well-known/openid-federation"


def fetch_jws_from_url(url: str, verify_ssl: bool = True) -> str:
    """Fetches a JWS from a given URL.

    :param url: The url to fetch the entity configuration from.
    :param verify_ssl: Whether to verify the SSL certificate of the entity ID. Defaults to True.
    :return: The JWS as a string.
    """
    response = requests.request("GET", url, verify=verify_ssl)

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


def get_self_signed_entity_configuration(
    entity_id: str, verify_ssl: bool = True
) -> dict:
    """Fetches the self-signed entity configuration of a given entity ID.

    :param entity_id: The entity ID to fetch the entity configuration from (URL).
    :param verify_ssl: Whether to verify the SSL certificate of the entity ID. Defaults to True.
    :return: The decoded entity configuration as a dictionary.
    """
    return get_payload(
        fetch_jws_from_url(well_known_url(entity_id), verify_ssl=verify_ssl)
    )


def fetch_entity_statement(
    entity_id: str, fetch_url: str, iss: str, verify_ssl: bool = True
) -> str:
    """Fetch an entity statement from a fetch endpoint.

    :param entity_id: The entity ID about which the entity statement is.
    :param fetch_url: the federation fetch endpoint.
    :param iss: the issuer of the entity statement.
    :param verify_ssl: Whether to verify the SSL certificate of the entity ID. Defaults to True.
    :return: The JWS entity statement as a string.
    """
    url = (
        fetch_url.rstrip("/")
        + "?iss="
        + urllib.parse.quote_plus(iss)
        + "&sub="
        + urllib.parse.quote_plus(entity_id)
    )
    return fetch_jws_from_url(url, verify_ssl=verify_ssl)


def build_trustchains(entity_id: str, verify_ssl: bool = True) -> dict:
    entity_configuration = get_self_signed_entity_configuration(
        entity_id, verify_ssl=verify_ssl
    )
    superiors = {}
    authority_hints = entity_configuration.get("authority_hints", [])
    for authority in authority_hints:
        superiors[authority] = build_trustchains(authority, verify_ssl=verify_ssl)
    return superiors


def print_json(data: dict):
    json.dump(data, click.get_text_stream("stdout"), indent=2)


def print_trustchains(trustchain: dict, indent: int = 0):
    """Prints a trustchain to stdout.

    :param trustchain: The trustchain to print.
    :param indent: The indentation level to use. Defaults to 0.
    """
    for superior, chain in trustchain.items():
        click.echo("\t" * indent + superior)
        print_trustchains(chain, indent + 1)

"""Executable for running oidcfed cli tool.
"""

import click
import functools

from oidcfed.api import (
    get_entity_configuration,
    get_entity_metadata,
    get_entity_jwks,
    get_trustchains,
    get_entity_statement,
    list_subordinates,
)
from oidcfed.utils import print_json, print_trustchains
from oidcfed.logging import logger


def safe_cli():
    try:
        cli()
    except Exception as e:
        logger.error(e)


def common_options(f):
    options = [
        click.option(
            "insecure",
            "--insecure",
            is_flag=True,
            default=False,
            help="Disable TLS certificate verification.",
            expose_value=True,
        ),
    ]
    return functools.reduce(lambda x, opt: opt(x), options, f)


@click.group(help="Tool for exploring an OIDC federation.")
def cli(**kwargs):
    """ """
    pass


@cli.group("entity", help="Commands for working with an entity in an OIDC federation.")
def entity(**kwargs):
    pass


@entity.command(
    "configuration",
    short_help="Prints the decoded self-signed entity configuration for given entity_id.",
)
@click.option(
    "verify",
    "--verify",
    is_flag=True,
    default=False,
    help="Verify the entity configuration's signature.",
)
@click.argument("entity_id")
@common_options
def configuration(entity_id: str, verify: bool, **kwargs):
    """
    Fetches an entity configuration and prints it to stdout.
    """
    print_json(
        get_entity_configuration(
            entity_id, verify=verify, verify_ssl=not kwargs["insecure"]
        )
    )


@entity.command("jwks", short_help="Prints the JWKS for given entity_id.")
@click.argument("entity_id")
@common_options
def jwks(entity_id: str, **kwargs):
    """
    Fetches an entity configuration and prints the JWKS to stdout.
    """
    print_json(get_entity_jwks(entity_id, verify_ssl=not kwargs["insecure"]))


@entity.command("metadata", short_help="Prints the metadata for given entity_id.")
@click.option(
    "verify",
    "--verify",
    is_flag=True,
    default=False,
    help="Verify the entity configuration's metadata.",
)
@click.argument("entity_id")
@common_options
def metadata(entity_id: str, verify: bool = False, **kwargs):
    """
    Fetches an entity configuration and prints the metadata to stdout.
    """
    print_json(
        get_entity_metadata(entity_id, verify=verify, verify_ssl=not kwargs["insecure"])
    )


@cli.command(
    "trustchains",
    help="Builds all trustchains for a given entity and prints them. If any trust anchor is specified, only trustchains ending in the trust anchor will be shown.",
)
@click.argument("entity_id")
@click.argument(
    "trust_anchor",
    metavar="TRUST_ANCHOR_ID",
    required=False,
    default="",
)
@common_options
def trustchains(entity_id: str, trust_anchor: str, **kwargs):
    """
    Build trustchain for a given entity and print it to stdout.
    """
    print_trustchains(
        get_trustchains(entity_id, trust_anchor, verify_ssl=not kwargs["insecure"])
    )


@cli.command(
    "fetch",
    short_help="Fetch an entity statement",
)
@click.argument("entity_id", metavar="ENTITY_ID")
@click.argument("issuer", metavar="ISSUER")
@common_options
def fetch(entity_id: str, issuer: str, **kwargs):
    """
    Fetch an entity statement for ENTITY_ID from ISSUER and print it to stdout.
    """
    print_json(
        get_entity_statement(entity_id, issuer, verify_ssl=not kwargs["insecure"])
    )


@cli.command("list", short_help="List all subordinate entities.")
@click.argument("entity_id", metavar="ENTITY_ID")
@click.option("--entity-type", metavar="TYPE", default=None)
@click.option("--trust-marked", is_flag=True, default=False)
@click.option("--trust-mark-id", metavar="ID", default=None)
@common_options
def federation_list(
    entity_id: str,
    entity_type: str | None,
    trust_marked: bool,
    trust_mark_id: str | None,
    **kwargs
):
    """Lists all subordinates of a federation entity."""
    click.echo(
        list_subordinates(
            entity_id=entity_id,
            entity_type=entity_type,
            trust_marked=trust_marked,
            trust_mark_id=trust_mark_id,
            verify_ssl=not kwargs["insecure"],
        )
    )


# command to build the subtree in the OIDC federation for a given entity

# command to build the paths between two entities in the OIDC federation

# command to show the modified metadata of an entity, given the other entity and the path between them

# command to diff the metadata of an entity before and after applying a metadata policy, given the starting trust anchor

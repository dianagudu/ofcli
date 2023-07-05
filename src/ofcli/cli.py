"""Executable for running ofcli cli tool.
"""

import click
import functools

from ofcli.api import (
    get_entity_configuration,
    get_entity_metadata,
    get_entity_jwks,
    get_trustchains,
    fetch_entity_statement,
    list_subordinates,
    discover,
    resolve_entity,
)
from ofcli.utils import print_json, print_trustchains, set_verify_ssl
from ofcli.logging import logger


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
            callback=set_verify_ssl,
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
    print_json(get_entity_configuration(entity_id, verify=verify))


@entity.command("jwks", short_help="Prints the JWKS for given entity_id.")
@click.argument("entity_id")
@common_options
def jwks(entity_id: str, **kwargs):
    """
    Fetches an entity configuration and prints the JWKS to stdout.
    """
    print_json(get_entity_jwks(entity_id))


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
    print_json(get_entity_metadata(entity_id, verify=verify))


@cli.command(
    "trustchains",
    help="Builds all trustchains for a given entity and prints them. If any trust anchor is specified, only trustchains ending in the trust anchor will be shown.",
)
@click.argument("entity_id")
@click.option(
    "--ta",
    "--trust-anchor",
    help="Trust anchor ID to use for building trustchains (multiple TAs possible).",
    metavar="TA_ID",
    required=False,
    default=[],
    multiple=True,
)
@click.option(
    "--export",
    help="Export trustchains to a dot file.",
    metavar="DOT_FILE",
    required=False,
    default=None,
    # add .dot extension if not present
    callback=lambda ctx, param, value: value
    if not value or value.endswith(".dot")
    else value + ".dot",
)
@common_options
def trustchains(entity_id: str, ta: tuple[str], export: str | None, **kwargs):
    """
    Build trustchain for a given entity and print it to stdout.
    """
    chains = get_trustchains(entity_id, list(ta), export)
    print_trustchains(chains)


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
    print_json(fetch_entity_statement(entity_id, issuer))


@cli.command("list", short_help="List all subordinate entities.")
@click.argument("entity_id", metavar="ENTITY_ID")
@click.option(
    "--entity-type",
    metavar="TYPE",
    default=None,
    type=click.Choice(
        ["openid_relying_party", "openid_provider", "federation_entity"],
        case_sensitive=False,
    ),
    help="Filter by entity type. Types: openid_relying_party, openid_provider, federation_entity.",
)
@click.option(
    "--trust-marked",
    is_flag=True,
    default=False,
    help="Only list trust marked entities.",
)
@click.option(
    "--trust-mark-id", metavar="ID", default=None, help="Filter by trust mark."
)
@common_options
def federation_list(
    entity_id: str,
    entity_type: str | None,
    trust_marked: bool,
    trust_mark_id: str | None,
    **kwargs
):
    """Lists all subordinates of a federation entity."""
    print_json(
        list_subordinates(
            entity_id=entity_id,
            entity_type=entity_type,
            trust_marked=trust_marked,
            trust_mark_id=trust_mark_id,
        )
    )


@cli.command(
    "discovery",
    short_help="Discover all OPs in the federation available to a given RP.",
)
@click.argument("entity_id", metavar="ENTITY_ID")
@click.option(
    "--ta",
    "--trust-anchor",
    help="Trust anchor ID (multiple TAs possible).",
    metavar="TA_ID",
    required=False,
    default=[],
    multiple=True,
)
@common_options
def discovery(entity_id: str, ta: tuple[str], **kwargs):
    """Discover all OPs in the federation available to a given RP."""
    logger.warn("Not implemented yet")
    # click.echo(discover(entity_id, list(ta)))


@cli.command(
    "resolve",
    short_help="Resolve metadata and Trust Marks for an entity, given a trust anchor.",
)
@click.argument("entity_id", metavar="ENTITY_ID")
@click.option(
    "--ta", "--trust-anchor", help="Trust anchor ID", metavar="TA_ID", required=True
)
@common_options
def resolve(entity_id: str, ta: str, **kwargs):
    """Resolve metadata and Trust Marks for an entity, given a trust anchor."""
    logger.warn("Not implemented yet")
    # print_json(resolve_entity(entity_id, ta))


# command to build the subtree in the OIDC federation for a given entity

# command to build the paths between two entities in the OIDC federation

# command to show the modified metadata of an entity, given the other entity and the path between them

# command to diff the metadata of an entity before and after applying a metadata policy, given the starting trust anchor

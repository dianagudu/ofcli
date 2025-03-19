"""Executable for running ofcli cli tool."""

from typing import Optional
import aiohttp
import click
import click_logging
from functools import wraps
import logging
import asyncio

from ofcli.core import (
    get_entity_configuration,
    get_entity_metadata,
    get_entity_jwks,
    get_trustchains,
    fetch_entity_statement,
    list_subordinates,
    discover,
    resolve_entity,
    subtree,
)
from ofcli.trustchain import print_trustchains
from ofcli.utils import (
    print_json,
    print_subtree,
    set_verify_ssl,
    print_version,
)
from ofcli.logging import logger
from ofcli.exceptions import InternalException


def safe_cli():
    try:
        cli()
    except Exception as e:
        logger.error(e)


def my_logging_simple_verbosity_option(logger=None, *names, **kwargs):
    """My version of @click_logging.simple_verbosity_option
    that takes over the value from the parent command.

    A decorator that adds a `--verbosity, -v` option to the decorated
    command.

    Name can be configured through ``*names``. Keyword arguments are passed to
    the underlying ``click.option`` decorator.
    """
    if not names:
        names = ["--verbosity", "-v"]

    kwargs.setdefault("default", "INFO")
    kwargs.setdefault("metavar", "LVL")
    kwargs.setdefault("expose_value", False)
    kwargs.setdefault(
        "help",
        f'Either CRITICAL, ERROR, WARNING, INFO or DEBUG. Default value: {kwargs["default"]}.',
    )
    kwargs.setdefault("is_eager", True)

    logger = click_logging.core._normalize_logger(logger)

    def decorator(f):
        def _set_level(ctx, param, value):
            value = value.upper()
            # check if log_level was set in the parent command and use it as default
            try:
                value = ctx.meta["log_level"]
            except Exception as e:
                # set the log_level in the context meta dict to be used by subcommands
                # only if it was set through the commandline
                if (
                    ctx.get_parameter_source(param.name)
                    is click.core.ParameterSource.COMMANDLINE
                ):
                    ctx.meta["log_level"] = value

            x = getattr(logging, value, None)
            if x is None:
                raise click.BadParameter(
                    "Must be CRITICAL, ERROR, WARNING, INFO or DEBUG, not {}".format(
                        value
                    )
                )
            logger.setLevel(x)

        return click.option(*names, callback=_set_level, **kwargs)(f)

    return decorator


def my_debug_option(logger=None, *names, **kwargs):
    """A decorator that adds a `--debug` option to the decorated command.

    Name can be configured through ``*names``. Keyword arguments are passed to
    the underlying ``click.option`` decorator.
    """
    if not names:
        names = ["--debug"]

    kwargs.setdefault("default", False)
    kwargs.setdefault("is_flag", True)
    kwargs.setdefault("expose_value", False)
    kwargs.setdefault("help", "Sets the log level to DEBUG.")
    kwargs.setdefault("is_eager", True)

    logger = click_logging.core._normalize_logger(logger)

    def decorator(f):
        def _set_debug(ctx, param, value):
            if value:
                # this option overwrites any parent option or --log-level options
                # when enabled, log level is always debug
                ctx.meta["log_level"] = "DEBUG"
                logger.setLevel(logging.DEBUG)

        return click.option(*names, callback=_set_debug, **kwargs)(f)

    return decorator


def common_options(f):
    @click.option(
        "insecure",
        "--insecure",
        is_flag=True,
        default=False,
        help="Disable TLS certificate verification.",
        expose_value=True,
        callback=set_verify_ssl,
    )
    @my_logging_simple_verbosity_option(
        logger,
        "--log-level",
        default="ERROR",
        metavar="LEVEL",
        envvar="LOG",
        show_envvar=True,
    )
    @my_debug_option(logger)
    @click.option(
        "--version",
        is_flag=True,
        expose_value=False,
        is_eager=True,
        callback=print_version,
        help="Print program version and exit.",
    )
    @wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@click.group(help="Tool for exploring an OIDC federation.")
@common_options
def cli(**kwargs):
    """ """
    pass


@cli.group("entity", help="Commands for working with an entity in an OIDC federation.")
@common_options
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
@coro
async def configuration(entity_id: str, verify: bool, **kwargs):
    """
    Fetches an entity configuration and prints it to stdout.
    """
    async with aiohttp.ClientSession() as http_session:
        print_json(
            await get_entity_configuration(
                entity_id=entity_id, verify=verify, http_session=http_session
            )
        )


@entity.command("jwks", short_help="Prints the JWKS for given entity_id.")
@click.argument("entity_id")
@common_options
@coro
async def jwks(entity_id: str, **kwargs):
    """
    Fetches an entity configuration and prints the JWKS to stdout.
    """
    async with aiohttp.ClientSession() as http_session:
        print_json(
            await get_entity_jwks(entity_id=entity_id, http_session=http_session)
        )


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
@coro
async def metadata(entity_id: str, verify: bool = False, **kwargs):
    """
    Fetches an entity configuration and prints the metadata to stdout.
    """
    async with aiohttp.ClientSession() as http_session:
        print_json(
            await get_entity_metadata(
                entity_id=entity_id, verify=verify, http_session=http_session
            )
        )


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
    callback=lambda ctx, param, value: (
        value if not value or value.endswith(".dot") else value + ".dot"
    ),
)
@click.option(
    "--details",
    help="Prints trustchains with additional details, including entity statements and expiration dates.",
    is_flag=True,
    default=False,
)
@common_options
@coro
async def trustchains(
    entity_id: str, ta: tuple[str], export: Optional[str], details: bool, **kwargs
):
    """
    Build trustchain for a given entity and print it to stdout.
    """
    async with aiohttp.ClientSession() as http_session:
        chains, graph = await get_trustchains(
            entity_id=entity_id,
            trust_anchors=list(ta),
            export_graph=export is not None,
            http_session=http_session,
        )
        print_trustchains(chains=chains, details=details)
        if export:
            if not graph:
                raise InternalException("No graph to export.")
            graph.write(export)


@cli.command(
    "fetch",
    short_help="Fetch an entity statement",
)
@click.argument("entity_id", metavar="ENTITY_ID")
@click.argument("issuer", metavar="ISSUER")
@common_options
@coro
async def fetch(entity_id: str, issuer: str, **kwargs):
    """
    Fetch an entity statement for ENTITY_ID from ISSUER and print it to stdout.
    """
    async with aiohttp.ClientSession() as http_session:
        print_json(
            await fetch_entity_statement(
                entity_id=entity_id, issuer=issuer, http_session=http_session
            )
        )


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
@coro
async def federation_list(
    entity_id: str,
    entity_type: Optional[str],
    trust_marked: bool,
    trust_mark_id: Optional[str],
    **kwargs,
):
    """Lists all subordinates of a federation entity."""
    async with aiohttp.ClientSession() as http_session:
        print_json(
            await list_subordinates(
                http_session=http_session,
                entity_id=entity_id,
                entity_type=entity_type,
                trust_marked=trust_marked,
                trust_mark_id=trust_mark_id,
            )
        )


@cli.command(
    "discovery",
    short_help="Discover all OPs in the federation available to a given RP. If no trust anchor is specified, all possible trust anchors will be used.",
)
@click.argument("entity_id", metavar="RP_ID")
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
@coro
async def discovery(entity_id: str, ta: tuple[str], **kwargs):
    """Discover all OPs in the federation available to a given RP."""
    async with aiohttp.ClientSession() as http_session:
        print_json(
            await discover(entity_id=entity_id, tas=list(ta), http_session=http_session)
        )


@cli.command(
    "resolve",
    short_help="Resolve metadata and Trust Marks for an entity, given a trust anchor and entity type.",
)
@click.argument("entity_id", metavar="ENTITY_ID")
@click.option(
    "--ta", "--trust-anchor", help="Trust anchor ID", metavar="TA_ID", required=True
)
@click.option(
    "--entity-type",
    metavar="TYPE",
    default=None,
    required=True,
    help="Entity type. Types: openid_relying_party, openid_provider, oauth_authorization_server, oauth_client, oauth_resource_server, federation_entity.",
    type=click.Choice(
        [
            "openid_relying_party",
            "openid_provider",
            "oauth_authorization_server",
            "oauth_client",
            "oauth_resource_server",
            "federation_entity",
        ]
    ),
)
@common_options
@coro
async def resolve(entity_id: str, ta: str, entity_type: str, **kwargs):
    """Resolve metadata and Trust Marks for an entity, given a trust anchor."""
    async with aiohttp.ClientSession() as http_session:
        metadata = await resolve_entity(
            entity_id=entity_id,
            ta=ta,
            entity_type=entity_type,
            http_session=http_session,
        )
        logger.debug("Resolved metadata: %s", metadata)
        print_json(metadata)


@cli.command(
    "subtree", short_help="Discover federation subtree using given entity as root."
)
@click.argument("entity_id", metavar="ENTITY_ID")
@click.option(
    "--export",
    help="Export tree to a dot file.",
    metavar="DOT_FILE",
    required=False,
    default=None,
    # add .dot extension if not present
    callback=lambda ctx, param, value: (
        value if not value or value.endswith(".dot") else value + ".dot"
    ),
)
@click.option(
    "--details",
    help="Prints subtree as json with additional details, including jwt entity configurations.",
    is_flag=True,
    default=False,
)
@common_options
@coro
async def get_subtree(entity_id: str, export: Optional[str], details: bool, **kwargs):
    """Discover all entities in the federation given by the root entity id and build tree."""
    # print_json(subtree(entity_id, export))
    async with aiohttp.ClientSession() as http_session:
        tree, graph = await subtree(
            http_session=http_session,
            entity_id=entity_id,
            export_graph=export is not None,
        )
        print_subtree(tree, details)
        if export:
            if not graph:
                raise InternalException("No graph to export.")
            graph.write(export)


# command to build the paths between two entities in the OIDC federation

# command to show the modified metadata of an entity, given the other entity and the path between them

# command to diff the metadata of an entity before and after applying a metadata policy, given the starting trust anchor

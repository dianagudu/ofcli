# oidcfed

This is a helper CLI tool for exploring OIDC federations.

## Installation

ofcli works with Python 3.7+.

The recommended way to install `ofcli` is with `pip`:

```bash
pip install ofcli
```

This will ensure that the stable version is fetched from pip, rather than the development version.

## Usage

```bash
Usage: ofcli [OPTIONS] COMMAND [ARGS]...

  Tool for exploring an OIDC federation.

Options:
  --insecure         Disable TLS certificate verification.
  --log-level LEVEL  Either CRITICAL, ERROR, WARNING, INFO or DEBUG. Default
                     value: ERROR.  [env var: LOG]
  --debug            Sets the log level to DEBUG.
  --version          Print program version and exit.
  --help             Show this message and exit.

Commands:
  discovery    Discover all OPs in the federation available to a given RP.
  entity       Commands for working with an entity in an OIDC federation.
  fetch        Fetch an entity statement
  list         List all subordinate entities.
  resolve      Resolve metadata and Trust Marks for an entity, given a trust
               anchor.
  trustchains  Builds all trustchains for a given entity and prints them.
```

For each subcommand, you can use the `--help` flag to get more information about the subcommand.

```bash
$ ofcli trustchains --help
Usage: ofcli trustchains [OPTIONS] ENTITY_ID

  Builds all trustchains for a given entity and prints them. If any trust
  anchor is specified, only trustchains ending in the trust anchor will be
  shown.

Options:
  --ta, --trust-anchor TA_ID  Trust anchor ID to use for building trustchains
                              (multiple TAs possible).
  --export DOT_FILE           Export trustchains to a dot file.
  --details                   Prints trustchains with additional details,
                              including entity statements and expiration
                              dates.
  --insecure                  Disable TLS certificate verification.
  --log-level LEVEL           Either CRITICAL, ERROR, WARNING, INFO or DEBUG.
                              Default value: ERROR.  [env var: LOG]
  --debug                     Sets the log level to DEBUG.
  --version                   Print program version and exit.
  --help                      Show this message and exit.
```

## Development

### Installing the development version

The development version of `ofcli` can be installed from the `main` branch of the [git repository](https://gitlab.software.geant.org/TI_Incubator/oidcfed/ofcli) and can be installed as follows (note the `-e` switch to install it in editable or "develop mode"):

```bash
git clone https://gitlab.software.geant.org/TI_Incubator/oidcfed/ofcli
cd ofcli
pip install -e .
```

### Versioning

Versions are managed by `bump2version`. To bump the version, run:

```bash
bump2version [major|minor|patch]
```

This will increase the version accordingly and commit the change.

### Build the package

```bash
python -m build --sdist --wheel
```

If you're running the [OIDCfed testbed](https://gitlab.geant.org/TI_Incubator/oidcfed/fedservice) locally with self-signed certificates, you'll first need to trust the mkcert CA certificate:

```bash
pip install certifi
cat "`mkcert -CAROOT`/rootCA.pem" >> `python -m certifi`
```

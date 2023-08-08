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
  discovery    Discover all OPs in the federation available to a given RP. If
               no trust anchor is specified, all possible trust anchors will
               be used.
  entity       Commands for working with an entity in an OIDC federation.
  fetch        Fetch an entity statement
  list         List all subordinate entities.
  resolve      Resolve metadata and Trust Marks for an entity, given a trust
               anchor and entity type.
  subtree      Discover federation subtree using given entity as root.
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

### Examples

Following, various example outputs.

1. Trustchains

```bash
$ ofcli trustchains https://op.fedservice.lh --export op-chains
* https://op.fedservice.lh -> https://trust-anchor.spid-cie.fedservice.lh/
* https://op.fedservice.lh -> https://umu.fedservice.lh -> https://swamid.fedservice.lh
* https://op.fedservice.lh -> https://umu.fedservice.lh -> https://seid.fedservice.lh
```

This will export the trust tree for the entity `https://op.fedservice.lh` to the file [examples/op-chains.dot](examples/op-chains.dot) in the [DOT language](https://en.wikipedia.org/wiki/DOT_(graph_description_language)).

The file can be converted to an image using the `dot` command from the [Graphviz](https://graphviz.org/) package (or any other tool that can read DOT files):

```bash
dot -Tpng examples/op-chains.dot -o examples/op-chains.png
```

![Trust tree for https://op.fedservice.lh](examples/op-chains.png)


2. Federation discovery

Discovering all entities in a sub-federation given by its root entity:

```bash
$ ofcli subtree https://swamid.fedservice.lh --export swamid-fed
{
  "https://swamid.fedservice.lh": {
    "https://umu.fedservice.lh": {
      "https://op.fedservice.lh": {}
    },
    "https://lu.fedservice.lh": {
      "https://auto.fedservice.lh": {}
    }
  }
}
```

This will export the federation tree for the entity `https://swamid.fedservice.lh` to the file [examples/swamid-fed.dot](examples/swamid-fed.json), which can be rendered as an image as described above.

![Federation tree for https://swamid.fedservice.lh](examples/swamid-fed.png)

3. Metadata resolution

Resolving metadata for an entity, given a trust anchor, will apply all metadata policies along the trustchain found for the given trust anchor, and return the resulting metadata.

```bash
$ ofcli resolve https://op.fedservice.lh --ta https://trust-anchor.spid-cie.fedservice.lh/ --entity-type openid_provider
```

This will return the metadata for the entity `https://op.fedservice.lh` as it would be seen by an entity that has `https://trust-anchor.spid-cie.fedservice.lh/` as a trust anchor (see [examples/op-resolved-metadata.json](examples/op-resolved-metadata.json)).

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

# oidcfed

## Build the package

```bash
python -m build --sdist --wheel
```

If you're running the [OIDCfed testbed](https://gitlab.geant.org/TI_Incubator/oidcfed/fedservice) locally with self-signed certificates, you'll first need to trust the mkcert CA certificate:

```bash
pip install certifi
cat "`mkcert -CAROOT`/rootCA.pem" >> `python -m certifi`
```

#!/bin/bash

update-ca-certificates 2>&1 > /dev/null
cat /etc/ssl/certs/ca-certificates.crt >> `python3 -m certifi`

exec python3 -m ofcli "$@"

FROM python:3.10 as base

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y graphviz graphviz-dev

RUN pip install ofcli

FROM base as ofcli

COPY ./entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

FROM base as ofapi

CMD ["uvicorn", "ofcli.api:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]

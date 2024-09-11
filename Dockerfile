FROM python:3.10 AS base

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y libgraphviz-dev

WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
RUN pip install .
RUN rm -rf /app

FROM base AS ofcli

COPY ./entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

FROM base AS ofapi

EXPOSE 80
CMD ["uvicorn", "ofcli.api:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]

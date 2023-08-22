FROM python:3.10

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y graphviz graphviz-dev

RUN pip install ofcli

CMD ["uvicorn", "ofcli.app:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]

from fastapi import FastAPI
from fastapi.exceptions import (
    RequestValidationError,
    ResponseValidationError,
)
from pydantic import ValidationError


from ofcli.exceptions import (
    validation_exception_handler,
    request_validation_exception_handler,
    internal_exception_handler,
    InternalException,
)

from ofcli.api.api_v1.api import api_router as api_router_v1
from ofcli.api.config import settings


def create_app():
    app = FastAPI(
        title=settings.title,
        description=settings.description,
        version=settings.version,
    )
    app.add_exception_handler(
        RequestValidationError, request_validation_exception_handler
    )
    app.add_exception_handler(ValidationError, validation_exception_handler)
    app.add_exception_handler(ResponseValidationError, validation_exception_handler)
    app.add_exception_handler(InternalException, internal_exception_handler)

    app.include_router(api_router_v1, prefix="", tags=["API"])
    app.include_router(api_router_v1, prefix=settings.API_V1_STR, tags=["API v1"])
    app.include_router(
        api_router_v1, prefix=settings.API_LATEST_STR, tags=["API latest"]
    )

    return app


app = create_app()


def main():
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--log-level", type=str, default="info")
    args = parser.parse_args()
    uvicorn.run(
        "ofcli.api:app", host="0.0.0.0", port=args.port, log_level=args.log_level
    )

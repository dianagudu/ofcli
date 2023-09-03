from pydantic_settings import BaseSettings
from ofcli import __version__


# define fastapi settings
class Settings(BaseSettings):
    title: str = "ofapi"
    description: str = "REST API to explore OpenId Connect Federations"
    version: str = __version__
    API_V1_STR: str = "/v1"
    API_LATEST_STR: str = "/latest"


settings = Settings()

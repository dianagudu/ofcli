from ofcli.utils import APIRouter

from ofcli.api.api_v1 import endpoints


api_router = APIRouter()
api_router.include_router(endpoints.router)

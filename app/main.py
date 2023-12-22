from fastapi import FastAPI

from app.api.routes.api import router as api_router
from app.core.config import API_PREFIX, DEBUG, PROJECT_NAME, VERSION
from sqlmodel import SQLModel, create_engine
from app.models.models import *


def get_application() -> FastAPI:
    application = FastAPI(title=PROJECT_NAME, debug=DEBUG, version=VERSION)
    application.include_router(api_router, prefix=API_PREFIX)
    return application


app = get_application()


@app.get("/")
def default_page():
    return "hi"

import os
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.database import engine
from app.models import user

from .auth import router as auth_router
from .routers import upload_routes, users_routes

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

origins = [
    "http://localhost:5173",  # Agrega tu frontend aquí
]


def get_application():
    _app = FastAPI(title=settings.PROJECT_NAME)
    _app.add_middleware(
        CORSMiddleware,
        # allow_origins=[str(origin)
        #                for origin in settings.BACKEND_CORS_ORIGINS],
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _app.include_router(users_routes.router, prefix="/api")
    _app.include_router(auth_router, prefix="/api")
    _app.include_router(upload_routes.router, prefix="/api")
    return _app


user.Base.metadata.create_all(bind=engine)
# user.Base.metadata.drop_all(bind=engine)
app = get_application()

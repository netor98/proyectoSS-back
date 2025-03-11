from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from app.core.config import settings
from app.models import user
from app.database import engine
from .routers import users_routes
from .auth import router as auth_router
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def get_application():
    _app = FastAPI(title=settings.PROJECT_NAME)
    _app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin)
                       for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _app.include_router(users_routes.router, prefix="/api")
    _app.include_router(auth_router, prefix="/api")
    return _app


user.Base.metadata.create_all(bind=engine)
app = get_application()

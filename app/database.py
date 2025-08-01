from .core.config import settings
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import as_declarative, declared_attr
from sqlalchemy import create_engine
import pymysql
pymysql.install_as_MySQLdb()


engine = create_engine(settings.DATABASE_URI, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@as_declarative()
class Base:

    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

from sqlalchemy import Column, Integer, String, Boolean
from ..database import Base


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(50), unique=True, index=True)
    employee_number = Column(String(10), unique=True)
    phone_number = Column(String(10), unique=True)
    first_names = Column(String(50), nullable=False)
    last_names = Column(String(50), nullable=False)
    hashed_password = Column(String(60))
    is_active = Column(Boolean, default=True)
    avatar = Column(String(255), nullable=True)  # Store file path or URL

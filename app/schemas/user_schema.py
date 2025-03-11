from pydantic import BaseModel
from typing import Optional


class UserBase(BaseModel):
    email: str
    first_names: str
    last_names: str
    hashed_password: str
    is_active: Optional[bool] = True


class UserCreate(UserBase):
    hashed_password: str


class UserUpdate(UserBase):
    hashed_password: str


class UserResponse(UserBase):
    id: int

    class Config:
        orm_mode = True

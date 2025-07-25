from typing import Optional

from pydantic import BaseModel


class UserBase(BaseModel):
    email: str
    first_names: str
    last_names: str
    employee_number: str
    phone_number: str
    hashed_password: str
    is_verified: Optional[bool] = False
    avatar: Optional[str] = None


class UserCreate(UserBase):
    hashed_password: str


class UserUpdate(BaseModel):
    email: Optional[str] = None
    first_names: Optional[str] = None
    last_names: Optional[str] = None
    employee_number: Optional[str] = None
    phone_number: Optional[str] = None
    hashed_password: Optional[str] = None
    is_verified: Optional[bool] = None
    avatar: Optional[str] = None


class UserResponse(UserBase):
    id: int

    class Config:
        orm_mode = True

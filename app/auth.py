from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

import jwt
from fastapi import (APIRouter, Cookie, Depends, Form, HTTPException, Response,
                     status)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.user_schema import UserCreate, UserResponse

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

SECRET_KEY = "f4b3e6b7b24b3b7f3f6b7b4"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Reduced to 15 minutes
REFRESH_TOKEN_EXPIRE_DAYS = 7     # 7 days for refresh token

# Password hashing
bcrypt = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_refresh_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")

        if email is None or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        return email
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    errors = []
    db_user = db.query(User).filter(User.email == user.email).first()

    employeeNum_user = db.query(User).filter(
        User.employee_number == user.employee_number).first()

    phoneNum_user = db.query(User).filter(
        User.phone_number == user.phone_number).first()

    if employeeNum_user:
        errors.append("Número de empleado ya registrado")

    if phoneNum_user:
        errors.append("Número de teléfono ya registrado")

    if db_user:
        errors.append("Correo ya registrado")

    if errors:
        raise HTTPException(status_code=400, detail=errors)

    hashed_password = bcrypt.hash(user.hashed_password)

    db_user = User(
        email=user.email,
        hashed_password=hashed_password,
        first_names=user.first_names,
        last_names=user.last_names,
        employee_number=user.employee_number,
        phone_number=user.phone_number,
    )

    # Add to database
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


@router.post("/token", response_model=Token)
async def login_for_access_token(
    user: UserLogin,
    response: Response,
    db: Session = Depends(get_db),
):
    userDB = db.query(User).filter(User.email == user.email).first()

    if not userDB or not bcrypt.verify(user.password, userDB.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create both access and refresh tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token(
        data={"sub": user.email},
        expires_delta=refresh_token_expires
    )

    # Set both tokens as HTTP-only cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax"
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax"
    )

    return {"access_token": access_token, "token_type": "bearer"}


def get_current_user(
    token: Annotated[str, Depends(oauth2_bearer)],
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception

    # Get user from database
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@router.post("/refresh", response_model=Token)
async def refresh_access_token(
    response: Response,
    refresh_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    # Verify refresh token and get user email
    email = verify_refresh_token(refresh_token)

    # Check if user exists
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Create new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token(
        data={"sub": email},
        expires_delta=access_token_expires
    )

    # Set new access token cookie
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax"
    )

    return {"access_token": new_access_token, "token_type": "bearer"}


@router.post("/logout")
async def logout(response: Response):
    # Clear both tokens
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"message": "Successfully logged out"}


@router.get("/profile", response_model=UserResponse)
def get_profile(
    access_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")

    try:
        print(access_token)
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")

        if email is None or token_type != "access":
            raise HTTPException(status_code=401, detail="Invalid token")

        # Fetch user from DB
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return user

    except InvalidTokenError:
        print("gg chaval")
        raise HTTPException(status_code=401, detail="Invalid access token")

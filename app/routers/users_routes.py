from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.database import get_db
from app.models.user import User
from app.schemas.user_schema import UserResponse, UserCreate, UserUpdate

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.get("/", response_model=list[UserResponse])
def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users


@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/", response_model=UserResponse)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = User(**user.dict())
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # Only update fields that are provided and not empty
        update_data = user.dict(exclude_unset=True)
        for key, value in update_data.items():
            if value is not None and value != "":
                setattr(db_user, key, value)

        db.commit()
        db.refresh(db_user)
        return db_user

    except IntegrityError as e:
        db.rollback()
        error_msg = str(e.orig)

        if "employee_number" in error_msg and "Duplicate entry" in error_msg:
            raise HTTPException(
                status_code=400,
                detail="El número de empleado ya está en uso"
            )
        elif "phone_number" in error_msg and "Duplicate entry" in error_msg:
            raise HTTPException(
                status_code=400,
                detail="El número de teléfono ya está en uso"
            )
        elif "email" in error_msg and "Duplicate entry" in error_msg:
            raise HTTPException(
                status_code=400,
                detail="El correo electrónico ya está en uso"
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="Error de integridad en la base de datos"
            )

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor"
        )


@router.delete("/{user_id}", response_model=UserResponse)
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return db_user

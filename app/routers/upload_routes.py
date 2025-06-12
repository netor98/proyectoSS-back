import os
import uuid
from typing import Optional

import jwt
from fastapi import APIRouter, Cookie, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from jwt.exceptions import InvalidTokenError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User

router = APIRouter(
    prefix="/upload",
    tags=["Upload"]
)

# Configuration
UPLOAD_DIR = "uploads/avatars"
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# JWT Configuration (should match auth.py)
SECRET_KEY = "f4b3e6b7b24b3b7f3f6b7b4"
ALGORITHM = "HS256"


def get_current_user_from_cookie(
    access_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    """Get current user from access token cookie"""
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")

        if email is None or token_type != "access":
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return user

    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid access token")


@router.post("/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Upload user avatar image"""

    # Validate file type
    file_extension = os.path.splitext(file.filename)[1].lower()
    if file_extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Validate file size
    file_content = await file.read()
    if len(file_content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB"
        )

    # Generate unique filename
    file_id = str(uuid.uuid4())
    filename = f"{file_id}{file_extension}"
    file_path = os.path.join(UPLOAD_DIR, filename)

    try:
        # Save file
        with open(file_path, "wb") as buffer:
            buffer.write(file_content)

        # Delete old avatar if exists
        if current_user.avatar:
            old_file_path = current_user.avatar
            if os.path.exists(old_file_path):
                os.remove(old_file_path)

        # Update user avatar in database
        current_user.avatar = filename 
        db.commit()
        db.refresh(current_user)

        return {
            "message": "Avatar uploaded successfully",
            "avatar_url": f"/api/upload/avatar/{filename}",
            "filename": filename
        }

    except Exception as e:
        # Clean up file if database update fails
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail="Failed to upload avatar")


@router.get("/avatar/{filename}")
async def get_avatar(filename: str):
    """Serve avatar image"""
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Avatar not found")

    return FileResponse(file_path)


@router.delete("/avatar")
async def delete_avatar(
    current_user: User = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Delete user avatar"""
    if not current_user.avatar:
        raise HTTPException(status_code=404, detail="No avatar to delete")

    # Delete file
    if os.path.exists(current_user.avatar):
        os.remove(current_user.avatar)

    # Update database
    current_user.avatar = None
    db.commit()

    return {"message": "Avatar deleted successfully"}

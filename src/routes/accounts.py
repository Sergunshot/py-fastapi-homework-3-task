import secrets
from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema
)
from src.schemas.accounts import (
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from src.security.passwords import hash_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    existing_user = db.query(UserModel).filter_by(UserModel.email == user_data.email).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    group = db.query(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER).first()
    hashed_password = hash_password(user_data.password)
    user = UserModel.create(user_data.email, hashed_password, group.id)

    try:
        db.add(user)
        db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)
        db.commit()

        db.refresh(user)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return user


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
def activate(activation_data: UserActivationRequestSchema, db: Session = Depends(get_db)):
    token_record = db.query(ActivationTokenModel).join(UserModel).filter(
        UserModel.email == activation_data.email,
        ActivationTokenModel.token == activation_data.token
    ).one_or_none()
    if (token_record is None
            or cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user = token_record.UserModel
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already active."
        )
    user.is_active = True
    db.delete(token_record)
    db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=PasswordResetRequestSchema,
    status_code=status.HTTP_200_OK
)
def password_reset_request(reset_data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == reset_data.email).first()
    if not user or not user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )
    db.query(PasswordResetTokenModel).filter_by(user_id=cast(int, user.id)).delete()
    generated_token = secrets.token_urlsafe(32)
    reset_token = PasswordResetTokenModel(token=generated_token, user_id=cast(int, user.id))
    db.add(reset_token)
    db.commit()
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=PasswordResetCompleteRequestSchema,
    status_code=status.HTTP_200_OK
)
def reset_password_complete(data: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    token_record = db.query(PasswordResetTokenModel).filter_by(user_id=user.id).first()
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if token_record.token != data.token or token_record.expires_at < datetime.now(timezone.utc):
        try:
            user.password = hash_password(data.password)
            db.delete(token_record)
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while resetting the password."
            )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED
)
def login(
        login_data: UserLoginRequestSchema,
        settings: BaseAppSettings = Depends(get_settings),
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = db.query(UserModel).filter(UserModel.email == login_data.email).first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token
        )
        db.add(refresh_token)
        db.flush()
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    jwt_access_token = jwt_manager.create_access_token({"user_id": user.id})

    return UserLoginResponseSchema(
        refresh_token=jwt_refresh_token,
        access_token=jwt_access_token,
    )


@router.post(
    "/api/v1/accounts/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
def refresh_token(
        token_data: TokenRefreshRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = decoded_token["user_id"]
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    refresh_token_record = db.query(RefreshTokenModel).filter_by(token=token_data.refresh_token).first()
    if not refresh_token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = db.query(UserModel).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return TokenRefreshResponseSchema(access_token=access_token)

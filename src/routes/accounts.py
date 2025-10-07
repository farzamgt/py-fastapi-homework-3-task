from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, BaseAppSettings, get_settings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    ActivationTokenModel
)
from src.enums.user_group_enum import UserGroupEnum
from exceptions import TokenExpiredError, InvalidTokenError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    MessageResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.passwords import hash_password


def ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


router = APIRouter()


@router.post(
    path="/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    existing_user = user_result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            detail=f"A user with this email {user_data.email} already exists.",
            status_code=status.HTTP_409_CONFLICT
        )

    role_result = await db.execute(
        select(UserGroupModel)
        .where(UserGroupModel.name == UserGroupEnum.USER)
    )
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(
            detail="A role with such name doesn't exist",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    try:
        hashed_password = hash_password(user_data.password)
        new_user = UserModel(
            email=user_data.email,
            _hashed_password=hashed_password,
            group=role
        )
        db.add(new_user)

        activation_token = ActivationTokenModel(
            user=new_user
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return UserRegistrationResponseSchema(
        id=new_user.id,
        email=new_user.email
    )


@router.post(
    path="/activate/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema
)
async def activate_user(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result_token = await db.execute(
        select(ActivationTokenModel)
        .join(UserModel)
        .options(joinedload(ActivationTokenModel.user))
        .where(
            ActivationTokenModel.token == user_data.token,
            UserModel.email == user_data.email
        )
    )
    activation_token = result_token.scalar_one_or_none()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    if ensure_utc(activation_token.expires_at) < datetime.now(timezone.utc):
        await db.delete(activation_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    user = activation_token.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    path="/password-reset/request/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema
)
async def reset_user_password(
        request_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result_user = await db.execute(
        select(UserModel).where(UserModel.email == request_data.email)
    )
    user = result_user.scalar_one_or_none()
    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        reset_token = PasswordResetTokenModel(user=user)
        db.add(reset_token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    path="/reset-password/complete/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema
)
async def reset_user_password_complete(
        request_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result_user = await db.execute(
        select(UserModel)
        .where(
            UserModel.email == request_data.email
        )
    )
    user = result_user.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            detail="Invalid email or token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    result_token = await db.execute(
        select(PasswordResetTokenModel)
        .where(
            PasswordResetTokenModel.user == user,
            PasswordResetTokenModel.token == request_data.token
        )
    )
    reset_token = result_token.scalar_one_or_none()
    if not reset_token:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user == user)
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    if ensure_utc(reset_token.expires_at) < datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = request_data.password
        await db.delete(reset_token)
        await db.commit()
        return MessageResponseSchema(
            message="Password reset successfully."
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    path="/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema
)
async def user_login(
        request_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    result_user = await db.execute(
        select(UserModel)
        .where(UserModel.email == request_data.email)
    )
    user = result_user.scalar_one_or_none()
    if not user or not user.verify_password(request_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_manager.create_access_token(
        data={
            "user_id": user.id,
            "email": user.email
        }
    )
    refresh_token = jwt_manager.create_refresh_token(
        data={
            "user_id": user.id,
            "email": user.email
        }
    )
    try:
        refresh_token_obj = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_obj)
        await db.commit()
        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    path="/refresh/",
    status_code=status.HTTP_200_OK,
    response_model=TokenRefreshResponseSchema
)
async def refresh_user_access_token(
        request_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        jwt_manager.decode_refresh_token(request_data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token."
        )

    result_token = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == request_data.refresh_token)
    )
    refresh_token = result_token.scalar_one_or_none()
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    result_user = await db.execute(
        select(UserModel)
        .where(UserModel.id == refresh_token.user_id)
    )
    user = result_user.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(
        data={
            "user_id": user.id,
            "email": user.email
        }
    )
    return TokenRefreshResponseSchema(
        access_token=new_access_token
    )

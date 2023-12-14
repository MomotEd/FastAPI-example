from fastapi import FastAPI, Depends, HTTPException
from passlib.context import CryptContext
from db import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
import models

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user_by_email(session: AsyncSession, email: str):
    result = await session.execute(
        select(models.UserStored).where(models.UserStored.email == email)
    )
    return result


@app.get("/")
async def root():
    return {"message": "Hello from Docker"}


@app.post("/register")
async def register_user(
    user: models.UserCreate, session: AsyncSession = Depends(get_session)
) -> models.User:
    db_user = await get_user_by_email(session, email=user.email)
    if db_user.first():
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hashed = get_password_hash(user.password)
    user_stored = models.UserStored(
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        password_hashed=password_hashed,
    )
    session.add(user_stored)
    await session.commit()
    await session.refresh(user_stored)
    return user

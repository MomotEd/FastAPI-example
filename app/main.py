from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from db import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
import models

SECRET_KEY = "0b84157f0c386f914baa9f5dbcb8eccc3b9718d35f6c705c7abb50d3cf106f7f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="authorize")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user_by_email(
    session: AsyncSession, email: str
) -> models.UserStored | None:
    result = await session.execute(
        select(models.UserStored).where(models.UserStored.email == email)
    )
    return result.scalars().first()


async def authenticate_user(
    session: AsyncSession, email: str, password: str
) -> models.User | None:
    db_user = await get_user_by_email(session, email)
    if not db_user:
        return None
    if not verify_password(password, db_user.password_hashed):
        return None
    return db_user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme), session: AsyncSession = Depends(get_session)
) -> models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user_by_email(session, email=email)
    if user is None:
        raise credentials_exception
    return user


@app.post("/authorize")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(OAuth2PasswordRequestForm),
    session: AsyncSession = Depends(get_session),
) -> models.Token:
    user = await authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return models.Token(access_token=access_token, token_type="bearer")


@app.get("/")
async def root(current_user=Depends(get_current_user)):
    return {"message": f"Hello {current_user.first_name}"}


@app.post("/register")
async def register_user(
    user: models.UserCreate, session: AsyncSession = Depends(get_session)
) -> models.User:
    db_user = await get_user_by_email(session, email=user.email)
    if db_user:
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


@app.post("/authorize-simple")
async def authorize_simple(
    user_cred: models.UserCred, session: AsyncSession = Depends(get_session)
) -> models.User:
    user = await authenticate_user(session, user_cred.email, user_cred.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    return user

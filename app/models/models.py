import datetime
from typing import Optional

from pydantic import validator, EmailStr
from sqlmodel import SQLModel, Field, Relationship


class User(SQLModel, table=True):
    id: Optional[int] = Field(primary_key=True)
    email: str
    username: str = Field(index=True)
    first_name: str
    last_name: str
    registered_at: datetime.datetime = datetime.datetime.now()
    password: str = Field(max_length=256, min_length=6)
    is_active: bool = False
    is_superuser: bool = False
    is_verified: bool = False


class UserInput(SQLModel):
    username: str
    password: str = Field(max_length=256, min_length=6)
    password2: str
    email: str
    is_seller: bool = False

    @validator("password2")
    def password_match(cls, v, values, **kwargs):
        if "password" in values and v != values["password"]:
            raise ValueError("passwords don't match")
        return v


class UserLogin(SQLModel):
    username: str
    password: str

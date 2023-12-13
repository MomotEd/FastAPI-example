from sqlmodel import SQLModel, Field
from pydantic import field_validator
from sqlalchemy import UniqueConstraint
from email_validator import validate_email, EmailNotValidError


class User(SQLModel):
    first_name: str
    last_name: str
    email: str

    @field_validator("email")
    @classmethod
    def is_email_valid(cls, value: str) -> str:
        try:
            validate_email(value)
        except EmailNotValidError:
            raise ValueError("Invalid email format")
        return value


class UserCreate(User):
    password: str


class UserStored(User, table=True):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email"),)
    id: int = Field(default=None, nullable=False, primary_key=True)
    password_hashed: str

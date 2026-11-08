"""The app's record of a signed-in user. Credentials stay in Supabase Auth."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel

from app.models.scan import utc_now

MAX_EMAIL_LENGTH = 320
MAX_NAME_LENGTH = 255


class Profile(SQLModel, table=True):
    __tablename__ = "profiles"

    # The Supabase user id, taken from a verified token.
    id: UUID = Field(primary_key=True)
    email: str | None = Field(default=None, max_length=MAX_EMAIL_LENGTH)
    name: str | None = Field(default=None, max_length=MAX_NAME_LENGTH)
    plan: str = Field(default="free", max_length=16)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

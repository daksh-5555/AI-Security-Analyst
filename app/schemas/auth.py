"""Request and response schemas for the identity lifecycle endpoints."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.emails import MAX_EMAIL_LENGTH
from app.core.security import (
    MAX_OPAQUE_TOKEN_LENGTH,
    validate_password_policy,
    validate_password_size,
)


class RegisterRequest(BaseModel):
    """Public self-registration payload.

    No role, activation, or verification field is accepted so clients cannot
    influence authorization state.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    email: str = Field(
        min_length=1,
        max_length=MAX_EMAIL_LENGTH,
        description="Account email address.",
    )
    password: str = Field(
        min_length=1,
        description="Account password. Minimum 12 characters; maximum 1024 UTF-8 bytes.",
    )

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        validate_password_policy(value)
        return value


class VerifyEmailRequest(BaseModel):
    """Email verification payload containing a single opaque action token."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    token: str = Field(
        min_length=1,
        max_length=MAX_OPAQUE_TOKEN_LENGTH,
        description="Opaque email verification token.",
    )


class ResendVerificationRequest(BaseModel):
    """Payload for re-requesting an email verification message."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    email: str = Field(
        min_length=1,
        max_length=MAX_EMAIL_LENGTH,
        description="Account email address.",
    )


class PasswordResetRequestPayload(BaseModel):
    """Payload for requesting a password reset message."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    email: str = Field(
        min_length=1,
        max_length=MAX_EMAIL_LENGTH,
        description="Account email address.",
    )


class PasswordResetConfirmRequest(BaseModel):
    """Payload for completing a password reset with a single-use token."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    token: str = Field(
        min_length=1,
        max_length=MAX_OPAQUE_TOKEN_LENGTH,
        description="Opaque password reset token.",
    )
    new_password: str = Field(
        min_length=1,
        description="New password. Minimum 12 characters; maximum 1024 UTF-8 bytes.",
    )

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        validate_password_policy(value)
        return value


class AuthMessageResponse(BaseModel):
    """Generic acknowledgement that deliberately reveals no account state."""

    model_config = ConfigDict(extra="forbid")

    message: str = Field(description="Generic, non-enumerating status message.")


class LoginRequest(BaseModel):
    """Credential payload for an existing account.

    Values are deliberately not format-validated beyond size so malformed input
    reaches the same generic credential-failure path as an unknown account.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    email: str = Field(
        max_length=MAX_EMAIL_LENGTH,
        description="Account email address.",
    )
    password: str = Field(
        description="Account password. Maximum 1024 UTF-8 bytes.",
    )

    @field_validator("password")
    @classmethod
    def validate_password_bytes(cls, value: str) -> str:
        validate_password_size(value)
        return value


class LoginResponse(BaseModel):
    """Successful login result. The refresh token is returned only once."""

    model_config = ConfigDict(extra="forbid")

    access_token: str = Field(description="Short-lived signed access token.")
    token_type: Literal["bearer"] = Field(
        default="bearer",
        description="Authorization scheme for the access token.",
    )
    expires_in: int = Field(description="Access-token lifetime in seconds.")
    refresh_token: str = Field(description="Opaque refresh token. Store only its hash.")
    refresh_expires_in: int = Field(description="Refresh-token lifetime in seconds.")
    session_id: UUID = Field(description="Persisted session identifier.")


class RefreshRequest(BaseModel):
    """Payload for rotating a refresh token.

    The token is deliberately not format-validated beyond its size so malformed
    values reach the same generic rejection path as unknown tokens. It is optional:
    a browser client may omit it and present the refresh token via the HttpOnly
    cookie instead (guarded by a double-submit CSRF check). An explicit body token
    always takes precedence over the cookie.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    refresh_token: str | None = Field(
        default=None,
        max_length=MAX_OPAQUE_TOKEN_LENGTH,
        description=(
            "Opaque refresh token issued by login or a previous rotation. Omit it to "
            "present the token via the HttpOnly refresh cookie instead."
        ),
    )


class RefreshResponse(LoginResponse):
    """Successful rotation result; same token envelope as login."""


class CurrentUserResponse(BaseModel):
    """Safe identity fields for the authenticated principal."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(description="User identifier.")
    email: str = Field(description="Account email address.")
    is_active: bool = Field(description="Whether the account is active.")
    is_email_verified: bool = Field(description="Whether the email is verified.")
    roles: list[str] = Field(description="Role names resolved from the database.")

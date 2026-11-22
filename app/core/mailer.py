"""Outbound email delivery abstraction.

Only the Python standard library is used. Implementations must never include a
raw action token in exception messages or logs; the token belongs only in the
message body delivered to the recipient.

The console backend exists for development and tests. Startup validation
rejects it in ``staging`` and ``production``.
"""

from __future__ import annotations

import smtplib
import ssl
import sys
from email.message import EmailMessage
from typing import Protocol, runtime_checkable

from app.core.config import SecurityConfigurationError, Settings, settings


class EmailDeliveryError(RuntimeError):
    """Raised when an outbound message could not be delivered.

    The message is deliberately generic so callers and logs never echo
    recipient details, message bodies, tokens, or SMTP credentials.
    """

    def __init__(self) -> None:
        super().__init__("Email delivery failed.")


@runtime_checkable
class Mailer(Protocol):
    """Minimal delivery interface used by the identity services."""

    def send(self, *, to: str, subject: str, body: str) -> None:
        """Deliver a plain-text message or raise ``EmailDeliveryError``."""


class ConsoleMailer:
    """Write messages to standard output for local development and tests."""

    def send(self, *, to: str, subject: str, body: str) -> None:
        sys.stdout.write(
            "\n"
            "----- BEGIN DEVELOPMENT EMAIL -----\n"
            f"To: {to}\n"
            f"Subject: {subject}\n"
            "\n"
            f"{body}\n"
            "----- END DEVELOPMENT EMAIL -----\n"
        )
        sys.stdout.flush()


class SmtpMailer:
    """Deliver plain-text messages through SMTP with optional TLS."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        sender: str,
        username: str | None = None,
        password: str | None = None,
        starttls: bool = True,
        use_ssl: bool = False,
        timeout_seconds: int = 10,
    ) -> None:
        self._host = host
        self._port = port
        self._sender = sender
        self._username = username
        self._password = password
        self._starttls = starttls
        self._use_ssl = use_ssl
        self._timeout_seconds = timeout_seconds

    def _connect(self) -> smtplib.SMTP:
        context = ssl.create_default_context()
        if self._use_ssl:
            return smtplib.SMTP_SSL(
                self._host,
                self._port,
                timeout=self._timeout_seconds,
                context=context,
            )
        return smtplib.SMTP(self._host, self._port, timeout=self._timeout_seconds)

    def send(self, *, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)

        try:
            with self._connect() as client:
                client.ehlo()
                if self._starttls and not self._use_ssl:
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                if self._username and self._password is not None:
                    client.login(self._username, self._password)
                client.send_message(message)
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            raise EmailDeliveryError() from exc


def _smtp_password(config: Settings) -> str | None:
    if config.smtp_password is None:
        return None
    return config.smtp_password.get_secret_value()


def build_mailer(config: Settings | None = None) -> Mailer:
    """Construct the configured mailer.

    Raises ``SecurityConfigurationError`` if the console backend is requested
    outside development and test, because printing tokens is not acceptable in
    deployed environments.
    """
    target = settings if config is None else config
    if target.email_backend == "smtp":
        return SmtpMailer(
            host=target.smtp_host,
            port=target.smtp_port,
            sender=target.email_from,
            username=target.smtp_username,
            password=_smtp_password(target),
            starttls=target.smtp_starttls,
            use_ssl=target.smtp_ssl,
            timeout_seconds=target.smtp_timeout_seconds,
        )
    if target.app_env in {"staging", "production"}:
        raise SecurityConfigurationError(
            "EMAIL_BACKEND=console is not permitted when APP_ENV is staging or production."
        )
    return ConsoleMailer()


def get_mailer() -> Mailer:
    """FastAPI dependency returning the configured mailer."""
    return build_mailer()

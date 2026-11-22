import smtplib

import pytest

from app.core.config import SecurityConfigurationError, Settings
from app.core.mailer import (
    ConsoleMailer,
    EmailDeliveryError,
    SmtpMailer,
    build_mailer,
)

TOKEN = "verify_abcdefghijklmnopqrstuvwxyz0123456789"


class FakeSmtp:
    instances: list["FakeSmtp"] = []

    def __init__(self, host: str, port: int, timeout: int | None = None, context=None) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.calls: list[object] = []
        self.messages: list[object] = []
        type(self).instances.append(self)

    def __enter__(self) -> "FakeSmtp":
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def starttls(self, *, context=None) -> None:
        self.calls.append(("starttls", context))

    def login(self, username: str, password: str) -> None:
        self.calls.append(("login", username, password))

    def send_message(self, message: object) -> None:
        self.messages.append(message)
        self.calls.append("send_message")


class FailingSmtp(FakeSmtp):
    def send_message(self, message: object) -> None:
        raise smtplib.SMTPServerDisconnected("connection lost")


@pytest.fixture(autouse=True)
def reset_fake_smtp() -> None:
    FakeSmtp.instances.clear()


def test_console_mailer_writes_message_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    ConsoleMailer().send(to="user@example.com", subject="Subject", body=f"Body {TOKEN}")

    output = capsys.readouterr().out
    assert "user@example.com" in output
    assert "Subject" in output
    assert TOKEN in output
    assert "BEGIN DEVELOPMENT EMAIL" in output


def test_smtp_mailer_uses_starttls_and_login(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    mailer = SmtpMailer(
        host="smtp.example.com",
        port=587,
        sender="no-reply@example.com",
        username="smtp-user",
        password="smtp-password",
        starttls=True,
        use_ssl=False,
        timeout_seconds=5,
    )

    mailer.send(to="recipient@example.com", subject="Verify", body=f"Token {TOKEN}")

    client = FakeSmtp.instances[0]
    assert client.host == "smtp.example.com"
    assert client.port == 587
    assert client.timeout == 5
    assert client.calls[0] == "ehlo"
    assert client.calls[1][0] == "starttls"
    assert client.calls[1][1] is not None
    assert client.calls[2] == "ehlo"
    assert client.calls[3] == ("login", "smtp-user", "smtp-password")
    assert client.calls[4] == "send_message"

    message = client.messages[0]
    assert message["From"] == "no-reply@example.com"
    assert message["To"] == "recipient@example.com"
    assert message["Subject"] == "Verify"
    assert TOKEN in message.get_content()


def test_smtp_mailer_uses_implicit_tls_without_starttls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSmtp)
    mailer = SmtpMailer(
        host="smtp.example.com",
        port=465,
        sender="no-reply@example.com",
        starttls=True,
        use_ssl=True,
    )

    mailer.send(to="recipient@example.com", subject="Verify", body="Body")

    client = FakeSmtp.instances[0]
    assert client.port == 465
    assert client.context is not None
    assert "starttls" not in client.calls
    assert not any(isinstance(call, tuple) and call[0] == "starttls" for call in client.calls)
    assert "send_message" in client.calls


def test_smtp_mailer_skips_login_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    mailer = SmtpMailer(host="smtp.example.com", port=25, sender="no-reply@example.com")

    mailer.send(to="recipient@example.com", subject="Verify", body="Body")

    client = FakeSmtp.instances[0]
    assert not any(isinstance(call, tuple) and call[0] == "login" for call in client.calls)


def test_smtp_failure_is_generic_and_hides_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(smtplib, "SMTP", FailingSmtp)
    mailer = SmtpMailer(host="smtp.example.com", port=25, sender="no-reply@example.com")

    with pytest.raises(EmailDeliveryError) as exc_info:
        mailer.send(to="recipient@example.com", subject="Verify", body=f"Token {TOKEN}")

    rendered = str(exc_info.value) + repr(exc_info.value)
    assert TOKEN not in rendered
    assert "recipient@example.com" not in rendered


def test_build_mailer_selects_console_for_development() -> None:
    config = Settings(_env_file=None, app_env="development", email_backend="console")

    assert isinstance(build_mailer(config), ConsoleMailer)


def test_build_mailer_selects_console_for_test() -> None:
    config = Settings(_env_file=None, app_env="test", email_backend="console")

    assert isinstance(build_mailer(config), ConsoleMailer)


def test_build_mailer_defaults_to_smtp() -> None:
    config = Settings(_env_file=None, app_env="test")

    assert isinstance(build_mailer(config), SmtpMailer)


def test_build_mailer_selects_smtp() -> None:
    config = Settings(_env_file=None, app_env="development", email_backend="smtp")

    assert isinstance(build_mailer(config), SmtpMailer)


def test_build_mailer_rejects_console_in_staging() -> None:
    config = Settings(_env_file=None, app_env="staging", email_backend="console")

    with pytest.raises(SecurityConfigurationError):
        build_mailer(config)


def test_build_mailer_rejects_console_in_production() -> None:
    config = Settings(_env_file=None, app_env="production", email_backend="console")

    with pytest.raises(SecurityConfigurationError):
        build_mailer(config)

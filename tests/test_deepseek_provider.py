"""DeepSeek explanation-provider adapter tests. Fully mocked — no network, and the
anthropic SDK itself is not required (a scripted fake is injected).

DeepSeek reuses the anthropic SDK against its Anthropic-compatible endpoint, so it
must: target the configured base URL and model, send a plain messages.create (no
output_config/effort/fallback betas), place the JSON schema in the system prompt,
map SDK errors to the same stable codes, and never leak the API key.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import Settings
from app.services.explanations.anthropic_provider import AnthropicExplanationProvider
from app.services.explanations.deepseek_provider import DeepSeekExplanationProvider
from app.services.explanations.provider import (
    ProviderError,
    ProviderErrorCode,
    ProviderRequest,
    ProviderResponse,
    build_provider,
)

DEEPSEEK_URL = "https://api.deepseek.com/anthropic"


# --- scripted fake anthropic SDK (same shape the real adapter expects) ---------
class _APIConnectionError(Exception):
    pass


class _APITimeoutError(_APIConnectionError):
    pass


class _APIStatusError(Exception):
    pass


class _RateLimitError(_APIStatusError):
    pass


class _AuthenticationError(_APIStatusError):
    pass


class _PermissionDeniedError(_APIStatusError):
    pass


class _BadRequestError(_APIStatusError):
    pass


class _InternalServerError(_APIStatusError):
    pass


def fake_sdk(client: Any) -> SimpleNamespace:
    created: list[dict[str, Any]] = []

    def factory(**kwargs: Any) -> Any:
        created.append(kwargs)
        return client

    return SimpleNamespace(
        Anthropic=factory,
        created=created,
        APIConnectionError=_APIConnectionError,
        APITimeoutError=_APITimeoutError,
        APIStatusError=_APIStatusError,
        RateLimitError=_RateLimitError,
        AuthenticationError=_AuthenticationError,
        PermissionDeniedError=_PermissionDeniedError,
        BadRequestError=_BadRequestError,
    )


class FakeMessages:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def fake_client(result: Any) -> SimpleNamespace:
    # beta is present but must never be used by the DeepSeek adapter.
    return SimpleNamespace(
        messages=FakeMessages(result), beta=SimpleNamespace(messages=FakeMessages(result))
    )


def message(stop_reason: str = "end_turn", text: str = "{}") -> SimpleNamespace:
    return SimpleNamespace(
        content=[
            SimpleNamespace(type="thinking", thinking=""),
            SimpleNamespace(type="text", text=text),
        ],
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=321, output_tokens=123),
        model="deepseek-flash",
    )


REQUEST = ProviderRequest(
    system="policy",
    user="data",
    json_schema={"type": "object", "marker": "schema-xyz"},
    max_output_tokens=4000,
)


def adapter(
    client: Any,
    *,
    api_key: str | None = "test-key",
    base_url: str | None = DEEPSEEK_URL,
) -> DeepSeekExplanationProvider:
    return DeepSeekExplanationProvider(
        model="deepseek-flash",
        api_key=api_key,
        base_url=base_url,
        timeout_seconds=30.0,
        max_retries=2,
        sdk=fake_sdk(client),
    )


# --- provider selection --------------------------------------------------------
def test_build_provider_selects_deepseek() -> None:
    config = Settings(
        _env_file=None,
        llm_provider="deepseek",
        llm_model="deepseek-flash",
        llm_base_url=DEEPSEEK_URL,
        llm_api_key="ds-key",
    )
    provider = build_provider(config)
    assert isinstance(provider, DeepSeekExplanationProvider)
    assert provider.name == "deepseek"
    assert provider.model == "deepseek-flash"
    assert provider._base_url == DEEPSEEK_URL


def test_build_provider_defaults_to_anthropic() -> None:
    provider = build_provider(Settings(_env_file=None, llm_api_key="k"))
    assert isinstance(provider, AnthropicExplanationProvider)
    assert provider.name == "anthropic"


# --- request shape -------------------------------------------------------------
def test_client_uses_base_url_and_model_without_anthropic_only_features() -> None:
    client = fake_client(message(text='{"ok": true}'))
    provider = adapter(client)
    response = provider.generate(REQUEST)

    assert response == ProviderResponse(
        text='{"ok": true}', model="deepseek-flash", input_tokens=321, output_tokens=123
    )
    # Client built against the DeepSeek base URL.
    assert provider._sdk.created == [
        {"api_key": "test-key", "base_url": DEEPSEEK_URL, "timeout": 30.0, "max_retries": 2}
    ]
    # Plain messages.create, never the beta endpoint.
    assert client.messages.calls and not client.beta.messages.calls
    call = client.messages.calls[0]
    assert call["model"] == "deepseek-flash" and call["max_tokens"] == 4000
    assert call["messages"] == [{"role": "user", "content": "data"}]
    # None of the Anthropic-only features the compat endpoint rejects.
    for forbidden in ("output_config", "betas", "fallbacks", "effort", "tools"):
        assert forbidden not in call


def test_schema_is_injected_into_the_system_prompt() -> None:
    client = fake_client(message())
    adapter(client).generate(REQUEST)
    system = client.messages.calls[0]["system"]
    assert system.startswith("policy")
    # The JSON schema is embedded so the model knows the exact output shape.
    assert "schema-xyz" in system
    assert "single JSON object" in system


# --- errors --------------------------------------------------------------------
@pytest.mark.parametrize(
    ("stop_reason", "code"),
    [("refusal", ProviderErrorCode.REFUSED), ("max_tokens", ProviderErrorCode.TRUNCATED)],
)
def test_stop_reasons(stop_reason: str, code: ProviderErrorCode) -> None:
    with pytest.raises(ProviderError) as excinfo:
        adapter(fake_client(message(stop_reason))).generate(REQUEST)
    assert excinfo.value.code is code
    assert (excinfo.value.input_tokens, excinfo.value.output_tokens) == (321, 123)


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (_APITimeoutError(), ProviderErrorCode.TIMEOUT),
        (_RateLimitError(), ProviderErrorCode.RATE_LIMITED),
        (_AuthenticationError(), ProviderErrorCode.NOT_CONFIGURED),
        (_PermissionDeniedError(), ProviderErrorCode.NOT_CONFIGURED),
        (_BadRequestError(), ProviderErrorCode.BAD_REQUEST),
        (_InternalServerError(), ProviderErrorCode.UNAVAILABLE),
        (_APIConnectionError(), ProviderErrorCode.UNAVAILABLE),
    ],
)
def test_maps_sdk_errors(error: Exception, code: ProviderErrorCode) -> None:
    with pytest.raises(ProviderError) as excinfo:
        adapter(fake_client(error)).generate(REQUEST)
    assert excinfo.value.code is code
    assert str(excinfo.value) == code.value  # a code only, no provider message text


def test_requires_api_key_and_base_url() -> None:
    with pytest.raises(ProviderError) as missing_key:
        adapter(None, api_key=None).generate(REQUEST)
    assert missing_key.value.code is ProviderErrorCode.NOT_CONFIGURED

    with pytest.raises(ProviderError) as missing_url:
        adapter(None, base_url=None).generate(REQUEST)
    assert missing_url.value.code is ProviderErrorCode.NOT_CONFIGURED


def test_sdk_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_name: str) -> Any:
        raise ImportError("No module named 'anthropic'")

    monkeypatch.setattr("importlib.import_module", missing)
    provider = DeepSeekExplanationProvider(
        model="deepseek-flash",
        api_key="k",
        base_url=DEEPSEEK_URL,
        timeout_seconds=1,
        max_retries=0,
    )
    with pytest.raises(ProviderError) as excinfo:
        provider.generate(REQUEST)
    assert excinfo.value.code is ProviderErrorCode.NOT_INSTALLED


# --- security ------------------------------------------------------------------
def test_api_key_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        adapter(fake_client(message(text='{"ok": true}')), api_key="super-secret-key").generate(
            REQUEST
        )
    assert "super-secret-key" not in caplog.text

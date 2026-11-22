"""Provider-neutral interface for explanation generation (M9).

A provider receives a fixed system policy, one redacted user message, and a
JSON schema; it returns raw text plus token usage, or raises ``ProviderError``
with a stable code. It is given no tools, so model output can never invoke
anything. Unit tests use a scripted fake; no test reaches a real provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from app.core.config import Settings, settings


class ProviderErrorCode(StrEnum):
    NOT_CONFIGURED = "provider_not_configured"
    NOT_INSTALLED = "provider_not_installed"
    TIMEOUT = "provider_timeout"
    RATE_LIMITED = "provider_rate_limited"
    UNAVAILABLE = "provider_unavailable"
    REFUSED = "provider_refused"
    TRUNCATED = "provider_output_truncated"
    BAD_REQUEST = "provider_bad_request"


class ProviderError(Exception):
    """A provider call failed. Carries no provider message text, only a code."""

    def __init__(
        self, code: ProviderErrorCode, *, input_tokens: int = 0, output_tokens: int = 0
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


@dataclass(frozen=True)
class ProviderRequest:
    system: str
    user: str
    json_schema: dict[str, Any]
    max_output_tokens: int


@dataclass(frozen=True)
class ProviderResponse:
    text: str
    model: str
    input_tokens: int
    output_tokens: int


class ExplanationProvider(Protocol):
    name: str
    model: str

    def generate(self, request: ProviderRequest) -> ProviderResponse: ...


def build_provider(config: Settings | None = None) -> ExplanationProvider:
    """The configured provider. The SDK is imported only when a call is made.

    Selection is centralized here (and therefore testable). Both providers use the
    same ``anthropic`` SDK; DeepSeek targets its Anthropic-compatible endpoint via
    ``llm_base_url``.
    """
    target = config or settings
    api_key = target.llm_api_key.get_secret_value() if target.llm_api_key else None

    if target.llm_provider == "deepseek":
        from app.services.explanations.deepseek_provider import DeepSeekExplanationProvider

        return DeepSeekExplanationProvider(
            model=target.llm_model,
            api_key=api_key,
            base_url=target.llm_base_url,
            timeout_seconds=target.llm_timeout_seconds,
            max_retries=target.llm_max_retries,
        )

    from app.services.explanations.anthropic_provider import AnthropicExplanationProvider

    return AnthropicExplanationProvider(
        model=target.llm_model,
        api_key=api_key,
        timeout_seconds=target.llm_timeout_seconds,
        max_retries=target.llm_max_retries,
        effort=target.llm_effort,
        refusal_fallback=target.llm_refusal_fallback,
    )


__all__ = [
    "ExplanationProvider",
    "ProviderError",
    "ProviderErrorCode",
    "ProviderRequest",
    "ProviderResponse",
    "build_provider",
]

"""Anthropic Claude adapter for explanations (M9, decision D12).

Uses the official ``anthropic`` SDK (optional ``[ai]`` extra), imported only
when a request is made, so the deterministic core installs and runs without it.

Request shape:

- ``output_config.format`` with a JSON schema (structured output) and
  ``output_config.effort``; no tools are offered;
- ``max_tokens`` bounded per finding;
- client ``timeout`` and ``max_retries`` from settings (the SDK retries
  timeouts, 429, and 5xx with backoff);
- with ``LLM_REFUSAL_FALLBACK`` (default on), the server-side ``fallbacks``
  parameter re-runs a declined request on the provider's default fallback model.

Egress note: the SDK connects to the provider's fixed API host itself, not
through ``GuardedHttpClient``. The host is not configurable here and never
derived from analysed content (ADR-0012).
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

from app.services.explanations.provider import (
    ProviderError,
    ProviderErrorCode,
    ProviderRequest,
    ProviderResponse,
)

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicExplanationProvider:
    name = "anthropic"

    def __init__(
        self,
        *,
        model: str,
        api_key: str | None,
        timeout_seconds: float,
        max_retries: int,
        effort: str,
        refusal_fallback: bool,
        client: Any | None = None,
        sdk: ModuleType | Any | None = None,
    ) -> None:
        self.model = model
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._effort = effort
        self._refusal_fallback = refusal_fallback
        self._client = client
        self._sdk = sdk

    def _module(self) -> Any:
        if self._sdk is None:
            try:
                self._sdk = importlib.import_module("anthropic")
            except ImportError as exc:
                raise ProviderError(ProviderErrorCode.NOT_INSTALLED) from exc
        return self._sdk

    def _get_client(self, sdk: Any) -> Any:
        if self._client is None:
            if not self._api_key:
                raise ProviderError(ProviderErrorCode.NOT_CONFIGURED)
            self._client = sdk.Anthropic(
                api_key=self._api_key,
                timeout=self._timeout,
                max_retries=self._max_retries,
            )
        return self._client

    def generate(self, request: ProviderRequest) -> ProviderResponse:
        sdk = self._module()
        client = self._get_client(sdk)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": request.max_output_tokens,
            "system": request.system,
            "messages": [{"role": "user", "content": request.user}],
            "output_config": {
                "effort": self._effort,
                "format": {"type": "json_schema", "schema": request.json_schema},
            },
        }
        # Most specific first: APITimeoutError subclasses APIConnectionError,
        # and the status errors subclass APIStatusError.
        try:
            if self._refusal_fallback:
                response = client.beta.messages.create(
                    **kwargs, betas=[FALLBACK_BETA], fallbacks="default"
                )
            else:
                response = client.messages.create(**kwargs)
        except sdk.APITimeoutError as exc:
            raise ProviderError(ProviderErrorCode.TIMEOUT) from exc
        except sdk.RateLimitError as exc:
            raise ProviderError(ProviderErrorCode.RATE_LIMITED) from exc
        except (sdk.AuthenticationError, sdk.PermissionDeniedError) as exc:
            raise ProviderError(ProviderErrorCode.NOT_CONFIGURED) from exc
        except sdk.BadRequestError as exc:
            raise ProviderError(ProviderErrorCode.BAD_REQUEST) from exc
        except sdk.APIStatusError as exc:
            raise ProviderError(ProviderErrorCode.UNAVAILABLE) from exc
        except sdk.APIConnectionError as exc:
            raise ProviderError(ProviderErrorCode.UNAVAILABLE) from exc

        usage = getattr(response, "usage", None)
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
        stop_reason = getattr(response, "stop_reason", None)
        if stop_reason == "refusal":
            raise ProviderError(
                ProviderErrorCode.REFUSED, input_tokens=input_tokens, output_tokens=output_tokens
            )
        if stop_reason == "max_tokens":
            raise ProviderError(
                ProviderErrorCode.TRUNCATED, input_tokens=input_tokens, output_tokens=output_tokens
            )
        # Thinking blocks may precede the answer; the structured output is text.
        text = next(
            (block.text for block in response.content if getattr(block, "type", None) == "text"),
            "",
        )
        return ProviderResponse(
            text=text,
            model=str(getattr(response, "model", None) or self.model)[:100],
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )


__all__ = ["AnthropicExplanationProvider", "FALLBACK_BETA"]

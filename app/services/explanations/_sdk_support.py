"""Shared plumbing for explanation providers built on the ``anthropic`` SDK.

Both the Anthropic provider and the DeepSeek provider (DeepSeek exposes an
Anthropic-compatible endpoint) use the same SDK, so they map SDK errors to stable
``ProviderErrorCode`` values and extract the text/usage from a Messages response
the same way. Only the request *shape* differs, which stays in each provider.

No provider message text is ever surfaced: errors carry a code only, never the
provider's message, and nothing here logs keys, headers, or request content.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.services.explanations.provider import (
    ProviderError,
    ProviderErrorCode,
    ProviderResponse,
)


def invoke_messages(sdk: Any, call: Callable[[], Any]) -> Any:
    """Run a Messages API call, mapping SDK exceptions to ProviderError codes.

    Order is most-specific first: ``APITimeoutError`` subclasses
    ``APIConnectionError``, and the status errors subclass ``APIStatusError``.
    Unknown exceptions propagate unchanged for the caller to record generically.
    """
    try:
        return call()
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


def response_from_message(response: Any, fallback_model: str) -> ProviderResponse:
    """Extract the text answer and token usage from a Messages response.

    Raises ``ProviderError`` for a refusal or a truncated (``max_tokens``) reply,
    carrying the usage so the budget still accounts for the spend.
    """
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
        model=str(getattr(response, "model", None) or fallback_model)[:100],
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )


__all__ = ["invoke_messages", "response_from_message"]

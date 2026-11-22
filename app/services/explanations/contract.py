"""Structured output contract for advisory finding explanations (M9).

The provider must return exactly this shape. Pydantic validation here is
authoritative; the JSON schema sent to the provider is a constraint-free copy
(``provider_json_schema``) because providers support only a subset of JSON
Schema keywords.

The contract deliberately has no status, severity, or confidence field: an
explanation cannot change the deterministic classification of a finding.
"""

from __future__ import annotations

import copy
from typing import Annotated, Any, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=600)]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]
Step = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]
Reference = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]


class GroundedClaim(BaseModel):
    """One factual statement and the supplied IDs that support it."""

    model_config = ConfigDict(extra="forbid")

    statement: Step = Field(description="One factual statement about this finding.")
    evidence_ids: list[Reference] = Field(
        min_length=1,
        max_length=20,
        description=(
            "IDs from the supplied data that support it: finding or evidence IDs, or "
            "reference-material IDs (kb:...) for remediation guidance."
        ),
    )


class FindingExplanationOutput(BaseModel):
    """What the provider must return for one finding."""

    model_config = ConfigDict(extra="forbid")

    summary: ShortText = Field(description="Two or three sentences for a non-specialist.")
    technical_explanation: Text = Field(description="How the issue works, from the evidence.")
    impact: Text = Field(description="What could happen if it is real; conditional language.")
    affected_component: ShortText = Field(description="File, route, parameter, or package.")
    evidence_references: list[Reference] = Field(
        min_length=1, max_length=50, description="Every supplied ID this explanation relies on."
    )
    claims: list[GroundedClaim] = Field(
        min_length=1, max_length=20, description="Every factual claim, each with its IDs."
    )
    remediation_steps: list[Step] = Field(min_length=1, max_length=15)
    validation_guidance: list[Step] = Field(
        min_length=1, max_length=10, description="How to verify the fix and retest."
    )
    uncertainty: Text = Field(description="What is unknown or not verified, and why.")
    source_references: list[Reference] = Field(
        default_factory=list,
        max_length=10,
        description="Reference-material IDs (kb:...) the remediation guidance relies on.",
    )

    def claim_ids(self) -> set[str]:
        ids: set[str] = set()
        for claim in self.claims:
            ids.update(claim.evidence_ids)
        return ids

    def referenced_ids(self) -> set[str]:
        return set(self.evidence_references) | self.claim_ids()

    def text_fields(self) -> list[str]:
        values = [
            self.summary,
            self.technical_explanation,
            self.impact,
            self.affected_component,
            self.uncertainty,
            *self.remediation_steps,
            *self.validation_guidance,
        ]
        values.extend(claim.statement for claim in self.claims)
        return values


_CONSTRAINT_KEYWORDS: Final = frozenset(
    {"minLength", "maxLength", "minItems", "maxItems", "title", "pattern", "default"}
)


def _strip(node: Any, definitions: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if "$ref" in node:
            name = node["$ref"].rsplit("/", 1)[-1]
            return _strip(copy.deepcopy(definitions[name]), definitions)
        return {
            key: _strip(value, definitions)
            for key, value in node.items()
            if key not in _CONSTRAINT_KEYWORDS and key != "$defs"
        }
    if isinstance(node, list):
        return [_strip(item, definitions) for item in node]
    return node


def provider_json_schema() -> dict[str, Any]:
    """Inlined, constraint-free schema with ``additionalProperties: false`` everywhere.

    Every property is required in the provider schema (an empty list is a valid
    answer), even where the Pydantic model has a default for older stored rows.
    """
    schema = FindingExplanationOutput.model_json_schema()
    stripped = _strip(schema, schema.get("$defs", {}))
    _require_all(stripped)
    return stripped


def _require_all(node: Any) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            node["required"] = list(node["properties"])
        for value in node.values():
            _require_all(value)
    elif isinstance(node, list):
        for value in node:
            _require_all(value)


__all__ = ["FindingExplanationOutput", "GroundedClaim", "provider_json_schema"]

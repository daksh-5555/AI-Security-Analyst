"""Dependency advisory audit tool (M3, ADR-0007).

Builds the dependency inventory, looks up exact versions with the advisory
provider, re-checks every provider match locally against the advisory's affected
ranges, and emits one ``dependency`` evidence record per (manifest, package,
version, advisory). Packages without an exact version, packages whose advisory
data is unavailable, and stale data are reported. A partially checked inventory
is never reported as clean.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from app.core.config import settings
from app.schemas.tooling import (
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceSourceType,
    ToolIdentity,
    ToolLimitation,
    ToolResult,
    ToolStatus,
)
from app.services.dependencies.inventory import (
    Dependency,
    DependencyInventory,
    build_inventory,
    is_dependency_file,
)
from app.services.dependencies.osv import (
    Advisory,
    AdvisoryCache,
    Freshness,
    OsvAdvisoryProvider,
    PackageQuery,
)
from app.services.dependencies.versions import RangeCheck, evaluate_affected
from app.services.net import GuardedHttpClient
from app.services.repository_targets import validate_repository_location
from app.services.tooling.protocol import ToolContext
from app.services.tooling.redaction import content_hash, evidence_key
from app.services.tooling.target_policy import NetworkSafetyPolicy

DEPENDENCY_AUDIT_STAGE: Final[str] = "dependency_audit"
TOOL_VERSION: Final[str] = "1.0.0"
RULE_ID: Final[str] = "dependency.osv_advisory"


def default_provider() -> OsvAdvisoryProvider:
    """Provider configured from settings; egress is limited to the OSV host."""
    cache = AdvisoryCache(
        settings.advisory_cache_dir, ttl_seconds=settings.advisory_cache_ttl_seconds
    )
    mode = "offline" if settings.dependency_audit_mode == "offline" else "online"
    client = None
    if mode == "online":
        host = urlsplit(settings.advisory_osv_base_url).hostname or ""
        policy = NetworkSafetyPolicy(
            allowed_schemes=frozenset({"https"}),
            total_timeout_seconds=float(settings.advisory_request_timeout_seconds),
            read_timeout_seconds=min(10.0, float(settings.advisory_request_timeout_seconds)),
            connect_timeout_seconds=min(5.0, float(settings.advisory_request_timeout_seconds)),
            max_response_bytes=16 * 1024 * 1024,
            allowed_content_types=frozenset({"application/json"}),
            max_requests_per_second=10.0,
            user_agent=f"AI-Security-Analyst/{settings.app_version} (dependency advisory lookup)",
        )
        client = GuardedHttpClient(policy, allowed_hosts=frozenset({host}))
    return OsvAdvisoryProvider(
        base_url=settings.advisory_osv_base_url, cache=cache, mode=mode, client=client
    )


def _severity(label: str | None) -> str:
    mapping = {
        "critical": "critical",
        "high": "high",
        "moderate": "medium",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get((label or "").strip().lower(), "unknown")


class DependencyAuditTool:
    """Inventory dependencies and match exact versions against advisories."""

    def __init__(self, provider: OsvAdvisoryProvider | None = None) -> None:
        self._provider = provider
        self._identity = ToolIdentity(
            name="dependency_auditor", version=TOOL_VERSION, rule_set_version="osv-ranges-1"
        )

    @property
    def identity(self) -> ToolIdentity:
        return self._identity

    def applies_to(self, context: ToolContext) -> bool:
        return context.discovery is not None and any(
            is_dependency_file(entry.relative_path) for entry in context.discovery.files
        )

    def run(self, context: ToolContext) -> ToolResult:
        discovery = context.discovery
        if discovery is None:
            raise ValueError("discovery inventory is required")
        started_at = context.clock()
        root = validate_repository_location(discovery.root)
        inventory = build_inventory(
            Path(root), discovery, max_bytes=settings.dependency_manifest_max_size_bytes
        )
        context.execution.check()

        provider = self._provider or default_provider()
        queries = sorted(
            {
                PackageQuery(dep.ecosystem, dep.name, dep.version)
                for dep in inventory.resolved
                if dep.version is not None
            },
            key=lambda query: (query.ecosystem.value, query.name.lower(), query.version),
        )
        limit = settings.advisory_max_packages
        checked_queries, overflow = queries[:limit], queries[limit:]
        lookup = provider.lookup(checked_queries, context.execution)

        evidence: dict[str, EvidenceRecord] = {}
        range_outcomes: Counter[str] = Counter()
        observed_at = context.clock()
        for dependency in inventory.resolved:
            query = PackageQuery(dependency.ecosystem, dependency.name, dependency.version or "")
            package = lookup.packages.get(query)
            if package is None:
                continue
            for advisory in package.advisories:
                record = self._evidence(dependency, advisory, observed_at, range_outcomes)
                if record is not None:
                    evidence.setdefault(record.evidence_key, record)

        freshness = Counter(package.freshness.value for package in lookup.packages.values())
        unavailable = freshness.get(Freshness.UNAVAILABLE.value, 0)
        stale = freshness.get(Freshness.STALE.value, 0)
        limitations = self._limitations(
            inventory, unavailable, stale, len(overflow), provider.mode, range_outcomes
        )
        incomplete = bool(
            inventory.unresolved or inventory.issues or unavailable or stale or overflow
            or range_outcomes.get(RangeCheck.UNSUPPORTED.value)
            or range_outcomes.get(RangeCheck.NOT_AFFECTED.value)
            or not discovery.summary.is_complete
        )  # fmt: skip
        counts = {
            "manifests_parsed": len(inventory.files_parsed),
            "dependencies": len(inventory.dependencies),
            "resolved_versions": len(inventory.resolved),
            "unresolved_versions": len(inventory.unresolved),
            "direct_dependencies": sum(
                1 for d in inventory.dependencies if d.relationship.value == "direct"
            ),
            "packages_checked": len(checked_queries) - unavailable,
            "packages_unchecked": unavailable + len(overflow),
            "stale_package_results": stale,
            "advisory_matches": len(evidence),
            "provider_requests": lookup.requests_made,
            "file_issues": len(inventory.issues),
        }
        return ToolResult(
            tool=self._identity,
            stage=DEPENDENCY_AUDIT_STAGE,
            status=ToolStatus.PARTIAL if incomplete else ToolStatus.COMPLETED,
            started_at=started_at,
            finished_at=context.clock(),
            counts=counts,
            evidence=[evidence[key] for key in sorted(evidence)],
            limitations=limitations,
        )

    def _evidence(
        self,
        dependency: Dependency,
        advisory: Advisory,
        observed_at: datetime,
        outcomes: Counter[str],
    ) -> EvidenceRecord | None:
        version = dependency.version or ""
        check = evaluate_affected(dependency.ecosystem, version, list(advisory.affected))
        outcomes[check.result.value] += 1
        location = EvidenceLocation(path=dependency.manifest)
        identity = f"{dependency.ecosystem.value}:{dependency.key[1]}:{version}:{advisory.id}"
        digest = content_hash(identity)
        limitations = [
            "Exploitability in this application was not assessed; this is a version match "
            "against a published advisory.",
        ]
        if advisory.freshness is Freshness.STALE:
            limitations.append("Advisory data came from an expired cache entry (stale).")
        if check.result is RangeCheck.NOT_AFFECTED:
            limitations.append(
                "The provider reported this advisory, but the local range check found the "
                "version outside every affected range."
            )
        return EvidenceRecord(
            evidence_key=evidence_key(self._identity.name, RULE_ID, location, digest),
            source_type=EvidenceSourceType.DEPENDENCY,
            provenance=EvidenceProvenance(
                tool=self._identity,
                rule_id=RULE_ID,
                observed_at=observed_at,
                method="OSV advisory lookup with local affected-range evaluation",
            ),
            location=location,
            summary=(
                f"{dependency.name} {version} ({dependency.ecosystem.value}) matches "
                f"{advisory.id}: {advisory.summary}"
            )[:1000],
            content_hash=digest,
            limitations=limitations,
            metadata={
                "ecosystem": dependency.ecosystem.value,
                "package": dependency.name,
                "version": version,
                "relationship": dependency.relationship.value,
                "dependency_source": dependency.source,
                "dev": dependency.dev,
                "advisory_id": advisory.id,
                "aliases": list(advisory.aliases),
                "cve_ids": list(advisory.cve_ids),
                "advisory_summary": advisory.summary,
                "severity": _severity(advisory.severity),
                "provider_severity": advisory.severity,
                "range_check": check.result.value,
                "match_explanation": check.explanation,
                "fixed_versions": list(check.fixed_versions),
                "published": advisory.published,
                "modified": advisory.modified,
                "source": "osv",
                "source_url": advisory.source_url,
                "fetched_at": advisory.fetched_at.isoformat(),
                "freshness": advisory.freshness.value,
            },
        )

    @staticmethod
    def _limitations(
        inventory: DependencyInventory,
        unavailable: int,
        stale: int,
        overflow: int,
        mode: str,
        outcomes: Counter[str],
    ) -> list[ToolLimitation]:
        items: list[ToolLimitation] = []
        if inventory.unresolved:
            names = sorted({dep.name for dep in inventory.unresolved})
            shown = ", ".join(names[:10]) + (", …" if len(names) > 10 else "")
            items.append(
                ToolLimitation(
                    code="unresolved_versions",
                    detail=(
                        f"{len(inventory.unresolved)} dependency declaration(s) have no exact "
                        f"version and no lock file, so they were not checked ({shown})."
                    )[:1000],
                )
            )
        if unavailable:
            items.append(
                ToolLimitation(
                    code="advisory_data_unavailable",
                    detail=(
                        f"Advisory data was unavailable for {unavailable} package version(s) "
                        f"(mode: {mode}); they are unchecked, not clean."
                    ),
                )
            )
        if stale:
            items.append(
                ToolLimitation(
                    code="stale_advisory_data",
                    detail=f"{stale} package result(s) used expired cached advisory data.",
                )
            )
        if overflow:
            items.append(
                ToolLimitation(
                    code="max_packages",
                    detail=f"{overflow} package version(s) exceeded ADVISORY_MAX_PACKAGES.",
                )
            )
        for path, reason in sorted(set(inventory.issues)):
            items.append(
                ToolLimitation(
                    code=f"file.{reason}",
                    detail=f"{path} could not be used ({reason.replace('_', ' ')}).",
                )
            )
        if outcomes.get(RangeCheck.UNSUPPORTED.value):
            items.append(
                ToolLimitation(
                    code="range_check_unsupported",
                    detail=(
                        f"{outcomes[RangeCheck.UNSUPPORTED.value]} advisory match(es) could not "
                        "be verified locally because a version could not be parsed."
                    ),
                )
            )
        if outcomes.get(RangeCheck.NOT_AFFECTED.value):
            items.append(
                ToolLimitation(
                    code="range_check_disagreement",
                    detail=(
                        f"{outcomes[RangeCheck.NOT_AFFECTED.value]} provider match(es) were not "
                        "confirmed by the local range check."
                    ),
                )
            )
        unique = {item.code: item for item in items}
        return [unique[code] for code in sorted(unique)][:50]


__all__ = ["DEPENDENCY_AUDIT_STAGE", "DependencyAuditTool", "default_provider"]

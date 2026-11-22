"""Dependency inventory and advisory matching (M3, ADR-0007)."""

from app.services.dependencies.auditor import DEPENDENCY_AUDIT_STAGE, DependencyAuditTool

__all__ = ["DEPENDENCY_AUDIT_STAGE", "DependencyAuditTool"]

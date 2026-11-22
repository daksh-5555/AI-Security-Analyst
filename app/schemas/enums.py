from enum import StrEnum


class AssessmentStatus(StrEnum):
    """Lifecycle state of an assessment."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AssessmentType(StrEnum):
    """Kind of assessment that can be scheduled."""

    REPOSITORY = "repository"
    WEB_SECURITY = "web_security"
    PERFORMANCE = "performance"


class AnalysisRunStatus(StrEnum):
    """Lifecycle state of one analysis run."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RepositorySourceKind(StrEnum):
    """Supported origins for a repository target."""

    LOCAL_PATH = "local_path"


class FindingSeverity(StrEnum):
    """Impact-oriented severity of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class FindingStatus(StrEnum):
    """Verification state of a finding."""

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"


class DiscoveryItemKind(StrEnum):
    """Kind of filesystem entry encountered during repository discovery."""

    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    OTHER = "other"


class DiscoverySkipReason(StrEnum):
    """Reason a filesystem entry was not included in the inventory."""

    EXCLUDED_DIRECTORY = "excluded_directory"
    SYMLINK = "symlink"
    NOT_REGULAR_FILE = "not_regular_file"
    PERMISSION_DENIED = "permission_denied"
    DISAPPEARED = "disappeared"
    INACCESSIBLE = "inaccessible"
    OUTSIDE_ROOT = "outside_root"
    MAX_DEPTH = "max_depth"
    MAX_FILE_COUNT = "max_file_count"
    MAX_TOTAL_SIZE = "max_total_size"


class DiscoveryTruncationReason(StrEnum):
    """Resource limit that caused the inventory to be truncated."""

    MAX_DEPTH = "max_depth"
    MAX_FILE_COUNT = "max_file_count"
    MAX_TOTAL_SIZE = "max_total_size"


class RoleName(StrEnum):
    """Canonical platform role names."""

    ADMIN = "Admin"
    SECURITY_ANALYST = "Security Analyst"
    VIEWER = "Viewer"


class UserActionTokenPurpose(StrEnum):
    """Purpose of a single-use user action token."""

    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"


class SessionRevocationReason(StrEnum):
    """Reason an authenticated session was revoked."""

    LOGOUT = "logout"
    PASSWORD_RESET = "password_reset"
    REFRESH_REUSE = "refresh_reuse"
    EXPIRED = "expired"
    USER_DEACTIVATED = "user_deactivated"
    ADMIN = "admin"


class AuditOutcome(StrEnum):
    """Whether an audited operation succeeded, failed, or was denied."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditAction(StrEnum):
    """Attributable security and lifecycle operations recorded in the audit trail."""

    ASSESSMENT_CREATED = "assessment.created"
    ASSESSMENT_ACCESS_DENIED = "assessment.access_denied"
    ASSESSMENT_LIFECYCLE_CHANGED = "assessment.lifecycle_changed"
    ASSESSMENT_LIFECYCLE_DENIED = "assessment.lifecycle_denied"
    REPOSITORY_TARGET_CREATED = "repository_target.created"
    ANALYSIS_RUN_QUEUED = "analysis_run.queued"
    ANALYSIS_RUN_STARTED = "analysis_run.started"
    ANALYSIS_RUN_COMPLETED = "analysis_run.completed"
    ANALYSIS_RUN_FAILED = "analysis_run.failed"
    ANALYSIS_RUN_CANCELLED = "analysis_run.cancelled"
    FINDING_EXPLANATION_CREATED = "finding_explanation.created"
    WORKFLOW_STARTED = "workflow.started"
    WORKFLOW_APPROVAL_RECORDED = "workflow.approval_recorded"
    WORKFLOW_FINISHED = "workflow.finished"
    ASSESSMENT_TARGET_AUTHORIZED = "assessment_target.authorized"
    ASSESSMENT_TARGET_REVOKED = "assessment_target.revoked"
    WEB_TARGET_LAB_SESSION_ESTABLISHED = "web_target.lab_session_established"
    WEB_TARGET_LAB_SESSION_CLEARED = "web_target.lab_session_cleared"


class AuditResourceType(StrEnum):
    """Kind of resource an audit event refers to."""

    ASSESSMENT = "assessment"
    REPOSITORY_TARGET = "repository_target"
    ANALYSIS_RUN = "analysis_run"
    ASSESSMENT_TARGET = "assessment_target"
    FINDING_EXPLANATION = "finding_explanation"
    WORKFLOW = "workflow"


class TargetType(StrEnum):
    """Kind of system an assessment target describes."""

    REPOSITORY = "repository"
    WEB_APPLICATION = "web_application"


class TargetStatus(StrEnum):
    """Authorization state of an assessment target. Only ``authorized`` may be analysed."""

    PENDING_AUTHORIZATION = "pending_authorization"
    AUTHORIZED = "authorized"
    REVOKED = "revoked"


class AuthorizationBasis(StrEnum):
    """Why a target is considered authorized."""

    OWNER_REGISTRATION = "owner_registration"
    EXPLICIT_CONFIRMATION = "explicit_confirmation"
    LEGACY_BACKFILL = "legacy_backfill"


class ExplanationStatus(StrEnum):
    """Outcome of one advisory LLM explanation attempt (M9)."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class WorkflowStatus(StrEnum):
    """Lifecycle of one bounded assessment workflow (M10)."""

    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

"""Pydantic request/response models for the web API."""
from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator


# --- Auth ---------------------------------------------------------------
class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str
    # OWASP ASVS 4.0.3 V2.1.1 (L1): user-set passwords must be at least 12
    # characters — was 6, which fails that requirement outright.
    password: str = Field(min_length=12)
    # When set, registration creates a brand-new, isolated organization with
    # this user as its Admin instead of joining the platform's default
    # organization — this is how a new company signs up for its own tenant.
    organization_name: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    organization_id: int
    mfa_enabled: bool = False


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut


class MfaRequiredOut(BaseModel):
    """Returned by /login instead of TokenOut when the account has MFA
    enabled — the caller must complete /auth/mfa/verify with this token."""
    mfa_required: bool = True
    mfa_token: str


class RefreshRequest(BaseModel):
    refresh_token: str


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=8)


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_url: str


class MfaEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MfaDisableRequest(BaseModel):
    password: str
    code: str = Field(min_length=6, max_length=8)


class RoleChangeRequest(BaseModel):
    role: str = Field(pattern="^(admin|security_manager|security_analyst|viewer)$")


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class ApiKeyOut(BaseModel):
    id: int
    name: str
    key_prefix: str
    created_at: str
    last_used_at: Optional[str] = None
    revoked_at: Optional[str] = None


class ApiKeyCreatedOut(ApiKeyOut):
    api_key: str  # shown exactly once, at creation


class MessageOut(BaseModel):
    """Generic success/status message body."""
    message: str


# --- Alerting (Phase 9) -----------------------------------------------------
class NotificationChannelCreate(BaseModel):
    channel_type: str = Field(pattern="^(email|webhook|slack|teams)$")
    name: str = Field(min_length=1, max_length=100)
    config: Dict[str, Any]


class NotificationChannelOut(BaseModel):
    id: int
    channel_type: str
    name: str
    config: Dict[str, Any]
    enabled: bool
    created_at: str


class NotificationOut(BaseModel):
    id: int
    channel_id: Optional[int] = None
    status: str
    error_message: Optional[str] = None
    sent_at: str


class AlertOut(BaseModel):
    id: int
    organization_id: int
    finding_id: int
    asset_id: Optional[int] = None
    severity: str
    status: str
    created_at: str
    last_notified_at: Optional[str] = None
    acknowledged_at: Optional[str] = None
    acknowledged_by_user_id: Optional[int] = None
    notifications: List[NotificationOut] = Field(default_factory=list)


# --- Remediation workflow (Phase 10) ----------------------------------------
class RemediationTaskCreate(BaseModel):
    finding_id: int
    assignee_user_id: Optional[int] = None
    team: Optional[str] = None
    priority: str = Field(default="medium", pattern="^(critical|high|medium|low)$")
    due_date: Optional[str] = None  # ISO date, e.g. "2026-10-15"


class RemediationTaskUpdate(BaseModel):
    assignee_user_id: Optional[int] = None
    team: Optional[str] = None
    priority: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low)$")
    due_date: Optional[str] = None
    # Manual moves only — FIX_SUBMITTED/RESCAN/VERIFICATION/FIXED/REOPENED
    # are exclusively driven by /submit-fix and the verification sweep.
    status: Optional[str] = Field(default=None, pattern="^(OPEN|ASSIGNED|IN_PROGRESS)$")


class RemediationCommentCreate(BaseModel):
    comment: str = Field(min_length=1, max_length=4000)


class RemediationCommentOut(BaseModel):
    id: int
    user_id: Optional[int] = None
    comment: str
    created_at: str


class RemediationTaskOut(BaseModel):
    id: int
    organization_id: int
    finding_id: int
    assignee_user_id: Optional[int] = None
    team: Optional[str] = None
    priority: str
    due_date: Optional[str] = None
    status: str
    verification_scan_id: Optional[int] = None
    verification_evidence: Optional[Dict[str, Any]] = None
    created_at: str
    updated_at: str
    comments: List[RemediationCommentOut] = Field(default_factory=list)


# --- Company Connector (Phase 8) --------------------------------------------
class EnrollmentTokenOut(BaseModel):
    enrollment_token: str  # shown once
    expires_at: str


class ConnectorEnrollRequest(BaseModel):
    enrollment_token: str
    name: str = Field(min_length=1, max_length=100)
    public_key_pem: str
    version: str = ""
    os: str = ""


class ConnectorEnrollOut(BaseModel):
    connector_id: int
    connector_secret: str  # shown once
    platform_public_key_pem: str


class ConnectorHeartbeatRequest(BaseModel):
    version: str = ""
    os: str = ""


class ConnectorOut(BaseModel):
    id: int
    organization_id: int
    name: str
    version: Optional[str] = None
    os: Optional[str] = None
    state: str  # ONLINE | OFFLINE | DEGRADED | REVOKED — live-computed
    paused: bool
    current_job_id: Optional[int] = None
    last_heartbeat_at: Optional[str] = None
    created_at: str


class ConnectorJobCreate(BaseModel):
    job_type: str = Field(pattern="^(inventory_check|configuration_check|"
                                  "vulnerability_assessment|telemetry_collection)$")
    scope: Dict[str, Any] = Field(default_factory=dict)


class ConnectorJobOut(BaseModel):
    id: int
    connector_id: int
    job_type: str
    scope: Dict[str, Any]
    status: str
    result: Optional[Dict[str, Any]] = None
    rejection_reason: Optional[str] = None
    created_at: str
    expires_at: str
    sent_at: Optional[str] = None
    completed_at: Optional[str] = None


class SignedJobOut(BaseModel):
    """What the connector actually receives from GET .../jobs/next — every
    one of these fields (except `signature` itself) is part of what the
    signature covers (see connector_crypto.job_signing_payload), so the
    connector can reconstruct the exact signed payload and verify it."""
    job_id: int
    organization_id: int
    connector_id: int
    job_type: str
    scope: Dict[str, Any]
    authorization: str
    created_at: str
    expires_at: str
    signature: str


class ConnectorJobResultSubmit(BaseModel):
    result: Dict[str, Any]
    signature: str


# --- Profile / Settings -------------------------------------------------
class ProfileUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    organization: Optional[str] = None
    job_title: Optional[str] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12)  # ASVS V2.1.1 (L1)


class SettingsUpdate(BaseModel):
    default_threads: Optional[int] = None
    default_timeout: Optional[int] = None
    verify_ssl: Optional[bool] = None
    accent: Optional[str] = None


# --- Scans --------------------------------------------------------------
class WebScanRequest(BaseModel):
    target: str
    vuln_types: List[str] = Field(default_factory=list)
    profile: Optional[str] = "web-full"
    threads: Optional[int] = 8
    scope_authorized: bool = False


class SystemScanRequest(BaseModel):
    target: str
    scan_mode: str = "fast"          # fast | full
    tools: List[str] = Field(default_factory=list)
    threads: int = 4
    scope_authorized: bool = False


class FindingOut(BaseModel):
    severity: str
    type: str
    description: str
    evidence: str = ""
    url: str = ""
    remediation: str = ""
    tool: str = ""
    parameter: Optional[str] = None
    payload: Optional[str] = None
    # Additive: the remediation engine's analyst report for this finding.
    analyst: Optional[Dict[str, Any]] = None


class FindingDetailOut(BaseModel):
    """Full vulnerability record (spec §13) — detection evidence is kept
    separate from remediation instructions, as required."""
    id: int
    scan_id: int
    organization_id: int
    title: str
    severity: str
    status: str
    confidence: str
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss_estimated: Optional[float] = None
    affected_component: str = ""
    occurrence_count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    # Risk engine (spec §10) — a composite score plus every contributing
    # factor, stored/reported separately so an admin can see why.
    risk_score: Optional[float] = None
    risk_factors: Optional[Dict[str, str]] = None
    # Detection evidence
    detection_method: str = ""
    evidence: str = ""
    affected_endpoint: str = ""
    parameter: Optional[str] = None
    payload: Optional[str] = None
    # Remediation — kept separate from the evidence above
    remediation: str = ""
    business_impact: Optional[str] = None
    technical_impact: Optional[str] = None


class FindingStatusUpdate(BaseModel):
    status: str = Field(pattern="^(NEW|OPEN|ACKNOWLEDGED|IN_PROGRESS|"
                                "FIX_PENDING_VERIFICATION|FIXED|REOPENED|"
                                "FALSE_POSITIVE|ACCEPTED_RISK)$")


class ScanOut(BaseModel):
    id: int
    target: str
    scan_type: str  # web | system
    status: str
    progress: float
    phase: str = ""
    message: str = ""
    findings: List[FindingOut] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    user_id: Optional[int] = None
    # Additive: {top_priorities: [...], issues: [...]} from the remediation engine.
    analyst_summary: Optional[Dict[str, Any]] = None


class ScanListItem(BaseModel):
    id: int
    target: str
    scan_type: str
    status: str
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    security_score: int = 0
    created_at: str = ""


# --- Organizations --------------------------------------------------------
class OrganizationOut(BaseModel):
    id: int
    name: str
    slug: str
    created_at: str
    user_count: int = 0
    asset_count: int = 0


# --- Assets -----------------------------------------------------------
class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    asset_type: str = Field(pattern="^(WEB_APPLICATION|COMPANY_CONNECTOR)$")
    url: str = Field(min_length=1)
    hostname: str = ""
    environment: str = Field(default="production",
                             pattern="^(production|staging|development|other)$")
    business_criticality: str = Field(default="medium",
                                      pattern="^(critical|high|medium|low)$")


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    environment: Optional[str] = Field(default=None,
                                       pattern="^(production|staging|development|other)$")
    business_criticality: Optional[str] = Field(default=None,
                                                pattern="^(critical|high|medium|low)$")
    monitoring_status: Optional[str] = Field(default=None,
                                             pattern="^(active|paused|inactive)$")


class AssetMonitoringUpdate(BaseModel):
    monitoring_status: str = Field(pattern="^(active|paused|inactive)$")
    monitoring_frequency: str = Field(pattern="^(manual|5m|15m|30m|hourly|daily|weekly)$")


class AssetOut(BaseModel):
    id: int
    organization_id: int
    asset_type: str
    name: str
    url: str
    hostname: str = ""
    environment: str
    business_criticality: str
    authorization_status: str
    monitoring_status: str
    monitoring_frequency: str = "manual"
    verification_status: str
    added_by_user_id: Optional[int] = None
    created_at: str
    updated_at: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    next_scan_at: Optional[str] = None
    last_scan_at: Optional[str] = None


# --- Reports ------------------------------------------------------------
class ReportOut(BaseModel):
    id: int
    scan_id: int
    target: str
    scan_type: str
    format: str
    path: str
    created_at: str


class DashboardStats(BaseModel):
    total_scans: int
    running_scans: int = 0
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    avg_security_score: int
    by_type: List[Dict[str, Any]] = Field(default_factory=list)
    recent_scans: List[ScanListItem] = Field(default_factory=list)
    trend: List[Dict[str, Any]] = Field(default_factory=list)
    # spec §11's explicit real-data dashboard fields
    total_assets: int = 0
    monitored_assets: int = 0
    connectors_online: int = 0
    connectors_offline: int = 0
    new_vulnerabilities: int = 0
    fixed_vulnerabilities: int = 0
    reopened_vulnerabilities: int = 0
    open_remediation_tasks: int = 0
    recent_alerts: List[Dict[str, Any]] = Field(default_factory=list)


class ScannerCatalogOut(BaseModel):
    categories: List[Dict[str, Any]] = Field(default_factory=list)
    all_keys: List[str] = Field(default_factory=list)
    default_keys: List[str] = Field(default_factory=list)
    profiles: List[str] = Field(default_factory=list)


# --- Admin info (Phase 20 audit: explicit output allowlist for a listing
# that has no other schema-level guard against a future sensitive-column
# leak — see webapp/db.py::list_users' own comment for the other half) -----
class AdminUserSummary(BaseModel):
    id: int
    username: str
    email: str
    role: str
    organization_id: int
    created_at: str
    mfa_enabled: bool = False


class AdminInfoOut(BaseModel):
    admin: str
    role: str
    users: List[AdminUserSummary] = Field(default_factory=list)
    jwt_ephemeral: bool
    jwt_configured: bool
    registration_open: bool


# --- Audit log (Phase 12, spec §18) -----------------------------------------
class AuditLogEntry(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    target_id: Optional[int] = None
    scan_id: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: str


# --- Remediation engine ("brain") live input ----------------------------
class BrainContext(BaseModel):
    exposure: Optional[Literal["internet_facing", "internal", "unknown"]] = None
    asset: Optional[str] = Field(default=None, max_length=200)


class BrainResolveRequest(BaseModel):
    """A described detected event from the operator's own monitored system.
    At least one of type / category / cwe / signal is required."""
    type: Optional[str] = Field(default=None, max_length=200)
    category: Optional[str] = Field(default=None, max_length=64)
    cwe: Optional[str] = Field(default=None, max_length=16, pattern=r"(?i)^CWE-\d{1,5}$")
    signal: Optional[str] = Field(default=None, max_length=500)
    confidence: Optional[Literal["confirmed", "needs_verification"]] = None
    context: Optional[BrainContext] = None

    @field_validator("type", "category", "cwe", "signal", mode="before")
    @classmethod
    def _strip(cls, v):
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("must be a string")
        v = v.strip()
        return v or None

    @model_validator(mode="after")
    def _at_least_one(self):
        if not any((self.type, self.category, self.cwe, self.signal)):
            raise ValueError("Provide at least one of: type, category, cwe, signal")
        if self.cwe:
            self.cwe = self.cwe.upper()
        if self.category:
            self.category = self.category.lower()
        return self

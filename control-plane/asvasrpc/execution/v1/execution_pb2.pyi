from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class JobStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    JOB_STATUS_UNSPECIFIED: _ClassVar[JobStatus]
    JOB_STATUS_SUCCEEDED: _ClassVar[JobStatus]
    JOB_STATUS_FAILED: _ClassVar[JobStatus]
    JOB_STATUS_TIMED_OUT: _ClassVar[JobStatus]
    JOB_STATUS_CANCELLED: _ClassVar[JobStatus]
    JOB_STATUS_DENIED: _ClassVar[JobStatus]

class ControlType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONTROL_TYPE_UNSPECIFIED: _ClassVar[ControlType]
    CONTROL_TYPE_CANCEL_ASSESSMENT: _ClassVar[ControlType]
    CONTROL_TYPE_EMERGENCY_STOP: _ClassVar[ControlType]
JOB_STATUS_UNSPECIFIED: JobStatus
JOB_STATUS_SUCCEEDED: JobStatus
JOB_STATUS_FAILED: JobStatus
JOB_STATUS_TIMED_OUT: JobStatus
JOB_STATUS_CANCELLED: JobStatus
JOB_STATUS_DENIED: JobStatus
CONTROL_TYPE_UNSPECIFIED: ControlType
CONTROL_TYPE_CANCEL_ASSESSMENT: ControlType
CONTROL_TYPE_EMERGENCY_STOP: ControlType

class Target(_message.Message):
    __slots__ = ("scheme", "host", "port")
    SCHEME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    scheme: str
    host: str
    port: int
    def __init__(self, scheme: _Optional[str] = ..., host: _Optional[str] = ..., port: _Optional[int] = ...) -> None: ...

class SecurityHeadersParams(_message.Message):
    __slots__ = ("path", "method", "max_redirects")
    PATH_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    MAX_REDIRECTS_FIELD_NUMBER: _ClassVar[int]
    path: str
    method: str
    max_redirects: int
    def __init__(self, path: _Optional[str] = ..., method: _Optional[str] = ..., max_redirects: _Optional[int] = ...) -> None: ...

class AllowedMethodsParams(_message.Message):
    __slots__ = ("path",)
    PATH_FIELD_NUMBER: _ClassVar[int]
    path: str
    def __init__(self, path: _Optional[str] = ...) -> None: ...

class TLSParams(_message.Message):
    __slots__ = ("expiry_warning_days",)
    EXPIRY_WARNING_DAYS_FIELD_NUMBER: _ClassVar[int]
    expiry_warning_days: int
    def __init__(self, expiry_warning_days: _Optional[int] = ...) -> None: ...

class ScopeTarget(_message.Message):
    __slots__ = ("host", "ports", "schemes")
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORTS_FIELD_NUMBER: _ClassVar[int]
    SCHEMES_FIELD_NUMBER: _ClassVar[int]
    host: str
    ports: _containers.RepeatedScalarFieldContainer[int]
    schemes: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, host: _Optional[str] = ..., ports: _Optional[_Iterable[int]] = ..., schemes: _Optional[_Iterable[str]] = ...) -> None: ...

class Authorization(_message.Message):
    __slots__ = ("statement", "reference", "authorized_by", "valid_from", "valid_until")
    STATEMENT_FIELD_NUMBER: _ClassVar[int]
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    AUTHORIZED_BY_FIELD_NUMBER: _ClassVar[int]
    VALID_FROM_FIELD_NUMBER: _ClassVar[int]
    VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    statement: str
    reference: str
    authorized_by: str
    valid_from: str
    valid_until: str
    def __init__(self, statement: _Optional[str] = ..., reference: _Optional[str] = ..., authorized_by: _Optional[str] = ..., valid_from: _Optional[str] = ..., valid_until: _Optional[str] = ...) -> None: ...

class Scope(_message.Message):
    __slots__ = ("targets", "allowed_cidrs", "excluded_cidrs", "authorization")
    TARGETS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_CIDRS_FIELD_NUMBER: _ClassVar[int]
    EXCLUDED_CIDRS_FIELD_NUMBER: _ClassVar[int]
    AUTHORIZATION_FIELD_NUMBER: _ClassVar[int]
    targets: _containers.RepeatedCompositeFieldContainer[ScopeTarget]
    allowed_cidrs: _containers.RepeatedScalarFieldContainer[str]
    excluded_cidrs: _containers.RepeatedScalarFieldContainer[str]
    authorization: Authorization
    def __init__(self, targets: _Optional[_Iterable[_Union[ScopeTarget, _Mapping]]] = ..., allowed_cidrs: _Optional[_Iterable[str]] = ..., excluded_cidrs: _Optional[_Iterable[str]] = ..., authorization: _Optional[_Union[Authorization, _Mapping]] = ...) -> None: ...

class TestingPolicy(_message.Message):
    __slots__ = ("allowed_tools", "approval_required_risk_tiers", "max_requests_per_second", "max_total_requests", "max_concurrency", "job_timeout_seconds", "max_wall_clock_minutes", "max_tokens", "max_planning_rounds", "max_plan_depth", "max_jobs", "max_attempts", "require_kernel_egress")
    ALLOWED_TOOLS_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUIRED_RISK_TIERS_FIELD_NUMBER: _ClassVar[int]
    MAX_REQUESTS_PER_SECOND_FIELD_NUMBER: _ClassVar[int]
    MAX_TOTAL_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    MAX_CONCURRENCY_FIELD_NUMBER: _ClassVar[int]
    JOB_TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    MAX_WALL_CLOCK_MINUTES_FIELD_NUMBER: _ClassVar[int]
    MAX_TOKENS_FIELD_NUMBER: _ClassVar[int]
    MAX_PLANNING_ROUNDS_FIELD_NUMBER: _ClassVar[int]
    MAX_PLAN_DEPTH_FIELD_NUMBER: _ClassVar[int]
    MAX_JOBS_FIELD_NUMBER: _ClassVar[int]
    MAX_ATTEMPTS_FIELD_NUMBER: _ClassVar[int]
    REQUIRE_KERNEL_EGRESS_FIELD_NUMBER: _ClassVar[int]
    allowed_tools: _containers.RepeatedScalarFieldContainer[str]
    approval_required_risk_tiers: _containers.RepeatedScalarFieldContainer[str]
    max_requests_per_second: int
    max_total_requests: int
    max_concurrency: int
    job_timeout_seconds: int
    max_wall_clock_minutes: int
    max_tokens: int
    max_planning_rounds: int
    max_plan_depth: int
    max_jobs: int
    max_attempts: int
    require_kernel_egress: bool
    def __init__(self, allowed_tools: _Optional[_Iterable[str]] = ..., approval_required_risk_tiers: _Optional[_Iterable[str]] = ..., max_requests_per_second: _Optional[int] = ..., max_total_requests: _Optional[int] = ..., max_concurrency: _Optional[int] = ..., job_timeout_seconds: _Optional[int] = ..., max_wall_clock_minutes: _Optional[int] = ..., max_tokens: _Optional[int] = ..., max_planning_rounds: _Optional[int] = ..., max_plan_depth: _Optional[int] = ..., max_jobs: _Optional[int] = ..., max_attempts: _Optional[int] = ..., require_kernel_egress: _Optional[bool] = ...) -> None: ...

class Approval(_message.Message):
    __slots__ = ("approval_id", "binding_hash", "expires_unix", "token")
    APPROVAL_ID_FIELD_NUMBER: _ClassVar[int]
    BINDING_HASH_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_UNIX_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    approval_id: str
    binding_hash: str
    expires_unix: int
    token: str
    def __init__(self, approval_id: _Optional[str] = ..., binding_hash: _Optional[str] = ..., expires_unix: _Optional[int] = ..., token: _Optional[str] = ...) -> None: ...

class JobEnvelope(_message.Message):
    __slots__ = ("version", "job_id", "attempt", "tenant_id", "assessment_id", "tool_id", "risk_tier", "category", "target", "security_headers", "allowed_methods", "tls", "max_requests", "requests_per_second", "timeout_seconds", "deadline_unix", "issued_unix", "scope", "policy", "approval")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    JOB_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    ASSESSMENT_ID_FIELD_NUMBER: _ClassVar[int]
    TOOL_ID_FIELD_NUMBER: _ClassVar[int]
    RISK_TIER_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    SECURITY_HEADERS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_METHODS_FIELD_NUMBER: _ClassVar[int]
    TLS_FIELD_NUMBER: _ClassVar[int]
    MAX_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    REQUESTS_PER_SECOND_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_UNIX_FIELD_NUMBER: _ClassVar[int]
    ISSUED_UNIX_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_FIELD_NUMBER: _ClassVar[int]
    version: int
    job_id: str
    attempt: int
    tenant_id: str
    assessment_id: str
    tool_id: str
    risk_tier: str
    category: str
    target: Target
    security_headers: SecurityHeadersParams
    allowed_methods: AllowedMethodsParams
    tls: TLSParams
    max_requests: int
    requests_per_second: int
    timeout_seconds: int
    deadline_unix: int
    issued_unix: int
    scope: Scope
    policy: TestingPolicy
    approval: Approval
    def __init__(self, version: _Optional[int] = ..., job_id: _Optional[str] = ..., attempt: _Optional[int] = ..., tenant_id: _Optional[str] = ..., assessment_id: _Optional[str] = ..., tool_id: _Optional[str] = ..., risk_tier: _Optional[str] = ..., category: _Optional[str] = ..., target: _Optional[_Union[Target, _Mapping]] = ..., security_headers: _Optional[_Union[SecurityHeadersParams, _Mapping]] = ..., allowed_methods: _Optional[_Union[AllowedMethodsParams, _Mapping]] = ..., tls: _Optional[_Union[TLSParams, _Mapping]] = ..., max_requests: _Optional[int] = ..., requests_per_second: _Optional[int] = ..., timeout_seconds: _Optional[int] = ..., deadline_unix: _Optional[int] = ..., issued_unix: _Optional[int] = ..., scope: _Optional[_Union[Scope, _Mapping]] = ..., policy: _Optional[_Union[TestingPolicy, _Mapping]] = ..., approval: _Optional[_Union[Approval, _Mapping]] = ...) -> None: ...

class PolicyDecision(_message.Message):
    __slots__ = ("allow", "require_approval", "approval_satisfied", "deny_reasons", "error", "engine", "plane")
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    REQUIRE_APPROVAL_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_SATISFIED_FIELD_NUMBER: _ClassVar[int]
    DENY_REASONS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    ENGINE_FIELD_NUMBER: _ClassVar[int]
    PLANE_FIELD_NUMBER: _ClassVar[int]
    allow: bool
    require_approval: bool
    approval_satisfied: bool
    deny_reasons: _containers.RepeatedScalarFieldContainer[str]
    error: str
    engine: str
    plane: str
    def __init__(self, allow: _Optional[bool] = ..., require_approval: _Optional[bool] = ..., approval_satisfied: _Optional[bool] = ..., deny_reasons: _Optional[_Iterable[str]] = ..., error: _Optional[str] = ..., engine: _Optional[str] = ..., plane: _Optional[str] = ...) -> None: ...

class Header(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: str
    def __init__(self, name: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class Request(_message.Message):
    __slots__ = ("method", "url", "scheme", "host", "port", "path", "resolved_ip")
    METHOD_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    SCHEME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_IP_FIELD_NUMBER: _ClassVar[int]
    method: str
    url: str
    scheme: str
    host: str
    port: int
    path: str
    resolved_ip: str
    def __init__(self, method: _Optional[str] = ..., url: _Optional[str] = ..., scheme: _Optional[str] = ..., host: _Optional[str] = ..., port: _Optional[int] = ..., path: _Optional[str] = ..., resolved_ip: _Optional[str] = ...) -> None: ...

class Response(_message.Message):
    __slots__ = ("status", "headers", "body_sha256", "body_len", "body_truncated", "body_excerpt", "tls_version")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_SHA256_FIELD_NUMBER: _ClassVar[int]
    BODY_LEN_FIELD_NUMBER: _ClassVar[int]
    BODY_TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    BODY_EXCERPT_FIELD_NUMBER: _ClassVar[int]
    TLS_VERSION_FIELD_NUMBER: _ClassVar[int]
    status: int
    headers: _containers.RepeatedCompositeFieldContainer[Header]
    body_sha256: str
    body_len: int
    body_truncated: bool
    body_excerpt: str
    tls_version: str
    def __init__(self, status: _Optional[int] = ..., headers: _Optional[_Iterable[_Union[Header, _Mapping]]] = ..., body_sha256: _Optional[str] = ..., body_len: _Optional[int] = ..., body_truncated: _Optional[bool] = ..., body_excerpt: _Optional[str] = ..., tls_version: _Optional[str] = ...) -> None: ...

class Redirect(_message.Message):
    __slots__ = ("location", "decision", "reason")
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    location: str
    decision: str
    reason: str
    def __init__(self, location: _Optional[str] = ..., decision: _Optional[str] = ..., reason: _Optional[str] = ...) -> None: ...

class TLSInfo(_message.Message):
    __slots__ = ("probe", "handshake", "version", "cipher_suite", "alpn", "verify_error", "hostname_error", "leaf_subject", "leaf_issuer", "leaf_sans", "leaf_not_before", "leaf_not_after", "leaf_sha256", "self_signed", "days_until_expiry", "expiry_warning_days", "chain_length")
    PROBE_FIELD_NUMBER: _ClassVar[int]
    HANDSHAKE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    CIPHER_SUITE_FIELD_NUMBER: _ClassVar[int]
    ALPN_FIELD_NUMBER: _ClassVar[int]
    VERIFY_ERROR_FIELD_NUMBER: _ClassVar[int]
    HOSTNAME_ERROR_FIELD_NUMBER: _ClassVar[int]
    LEAF_SUBJECT_FIELD_NUMBER: _ClassVar[int]
    LEAF_ISSUER_FIELD_NUMBER: _ClassVar[int]
    LEAF_SANS_FIELD_NUMBER: _ClassVar[int]
    LEAF_NOT_BEFORE_FIELD_NUMBER: _ClassVar[int]
    LEAF_NOT_AFTER_FIELD_NUMBER: _ClassVar[int]
    LEAF_SHA256_FIELD_NUMBER: _ClassVar[int]
    SELF_SIGNED_FIELD_NUMBER: _ClassVar[int]
    DAYS_UNTIL_EXPIRY_FIELD_NUMBER: _ClassVar[int]
    EXPIRY_WARNING_DAYS_FIELD_NUMBER: _ClassVar[int]
    CHAIN_LENGTH_FIELD_NUMBER: _ClassVar[int]
    probe: str
    handshake: bool
    version: str
    cipher_suite: str
    alpn: str
    verify_error: str
    hostname_error: str
    leaf_subject: str
    leaf_issuer: str
    leaf_sans: _containers.RepeatedScalarFieldContainer[str]
    leaf_not_before: str
    leaf_not_after: str
    leaf_sha256: str
    self_signed: bool
    days_until_expiry: int
    expiry_warning_days: int
    chain_length: int
    def __init__(self, probe: _Optional[str] = ..., handshake: _Optional[bool] = ..., version: _Optional[str] = ..., cipher_suite: _Optional[str] = ..., alpn: _Optional[str] = ..., verify_error: _Optional[str] = ..., hostname_error: _Optional[str] = ..., leaf_subject: _Optional[str] = ..., leaf_issuer: _Optional[str] = ..., leaf_sans: _Optional[_Iterable[str]] = ..., leaf_not_before: _Optional[str] = ..., leaf_not_after: _Optional[str] = ..., leaf_sha256: _Optional[str] = ..., self_signed: _Optional[bool] = ..., days_until_expiry: _Optional[int] = ..., expiry_warning_days: _Optional[int] = ..., chain_length: _Optional[int] = ...) -> None: ...

class Exchange(_message.Message):
    __slots__ = ("seq", "request", "response", "redirect", "tls", "error", "started_unix_ms", "duration_ms")
    SEQ_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    REDIRECT_FIELD_NUMBER: _ClassVar[int]
    TLS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STARTED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    seq: int
    request: Request
    response: Response
    redirect: Redirect
    tls: TLSInfo
    error: str
    started_unix_ms: int
    duration_ms: int
    def __init__(self, seq: _Optional[int] = ..., request: _Optional[_Union[Request, _Mapping]] = ..., response: _Optional[_Union[Response, _Mapping]] = ..., redirect: _Optional[_Union[Redirect, _Mapping]] = ..., tls: _Optional[_Union[TLSInfo, _Mapping]] = ..., error: _Optional[str] = ..., started_unix_ms: _Optional[int] = ..., duration_ms: _Optional[int] = ...) -> None: ...

class JobResult(_message.Message):
    __slots__ = ("job_id", "attempt", "tenant_id", "assessment_id", "worker_id", "status", "error", "policy_decision", "backend", "egress_mode", "requests_used", "exchanges", "sandbox_attestation", "started_unix", "finished_unix")
    class SandboxAttestationEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    JOB_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    ASSESSMENT_ID_FIELD_NUMBER: _ClassVar[int]
    WORKER_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    POLICY_DECISION_FIELD_NUMBER: _ClassVar[int]
    BACKEND_FIELD_NUMBER: _ClassVar[int]
    EGRESS_MODE_FIELD_NUMBER: _ClassVar[int]
    REQUESTS_USED_FIELD_NUMBER: _ClassVar[int]
    EXCHANGES_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ATTESTATION_FIELD_NUMBER: _ClassVar[int]
    STARTED_UNIX_FIELD_NUMBER: _ClassVar[int]
    FINISHED_UNIX_FIELD_NUMBER: _ClassVar[int]
    job_id: str
    attempt: int
    tenant_id: str
    assessment_id: str
    worker_id: str
    status: JobStatus
    error: str
    policy_decision: PolicyDecision
    backend: str
    egress_mode: str
    requests_used: int
    exchanges: _containers.RepeatedCompositeFieldContainer[Exchange]
    sandbox_attestation: _containers.ScalarMap[str, str]
    started_unix: int
    finished_unix: int
    def __init__(self, job_id: _Optional[str] = ..., attempt: _Optional[int] = ..., tenant_id: _Optional[str] = ..., assessment_id: _Optional[str] = ..., worker_id: _Optional[str] = ..., status: _Optional[_Union[JobStatus, str]] = ..., error: _Optional[str] = ..., policy_decision: _Optional[_Union[PolicyDecision, _Mapping]] = ..., backend: _Optional[str] = ..., egress_mode: _Optional[str] = ..., requests_used: _Optional[int] = ..., exchanges: _Optional[_Iterable[_Union[Exchange, _Mapping]]] = ..., sandbox_attestation: _Optional[_Mapping[str, str]] = ..., started_unix: _Optional[int] = ..., finished_unix: _Optional[int] = ...) -> None: ...

class ControlMessage(_message.Message):
    __slots__ = ("type", "tenant_id", "assessment_id", "reason", "issued_unix")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    ASSESSMENT_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    ISSUED_UNIX_FIELD_NUMBER: _ClassVar[int]
    type: ControlType
    tenant_id: str
    assessment_id: str
    reason: str
    issued_unix: int
    def __init__(self, type: _Optional[_Union[ControlType, str]] = ..., tenant_id: _Optional[str] = ..., assessment_id: _Optional[str] = ..., reason: _Optional[str] = ..., issued_unix: _Optional[int] = ...) -> None: ...

class GetStatusRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class WorkerStatus(_message.Message):
    __slots__ = ("worker_id", "backend", "isolation_level", "egress_mode", "note", "slots", "running_jobs", "policy_sha256", "version", "uid", "loopback_targets_allowed", "started_unix", "now_unix")
    WORKER_ID_FIELD_NUMBER: _ClassVar[int]
    BACKEND_FIELD_NUMBER: _ClassVar[int]
    ISOLATION_LEVEL_FIELD_NUMBER: _ClassVar[int]
    EGRESS_MODE_FIELD_NUMBER: _ClassVar[int]
    NOTE_FIELD_NUMBER: _ClassVar[int]
    SLOTS_FIELD_NUMBER: _ClassVar[int]
    RUNNING_JOBS_FIELD_NUMBER: _ClassVar[int]
    POLICY_SHA256_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    UID_FIELD_NUMBER: _ClassVar[int]
    LOOPBACK_TARGETS_ALLOWED_FIELD_NUMBER: _ClassVar[int]
    STARTED_UNIX_FIELD_NUMBER: _ClassVar[int]
    NOW_UNIX_FIELD_NUMBER: _ClassVar[int]
    worker_id: str
    backend: str
    isolation_level: str
    egress_mode: str
    note: str
    slots: int
    running_jobs: int
    policy_sha256: str
    version: str
    uid: int
    loopback_targets_allowed: bool
    started_unix: int
    now_unix: int
    def __init__(self, worker_id: _Optional[str] = ..., backend: _Optional[str] = ..., isolation_level: _Optional[str] = ..., egress_mode: _Optional[str] = ..., note: _Optional[str] = ..., slots: _Optional[int] = ..., running_jobs: _Optional[int] = ..., policy_sha256: _Optional[str] = ..., version: _Optional[str] = ..., uid: _Optional[int] = ..., loopback_targets_allowed: _Optional[bool] = ..., started_unix: _Optional[int] = ..., now_unix: _Optional[int] = ...) -> None: ...

class SignedControl(_message.Message):
    __slots__ = ("control_message", "sig")
    CONTROL_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SIG_FIELD_NUMBER: _ClassVar[int]
    control_message: bytes
    sig: str
    def __init__(self, control_message: _Optional[bytes] = ..., sig: _Optional[str] = ...) -> None: ...

class ControlAck(_message.Message):
    __slots__ = ("jobs_signalled",)
    JOBS_SIGNALLED_FIELD_NUMBER: _ClassVar[int]
    jobs_signalled: int
    def __init__(self, jobs_signalled: _Optional[int] = ...) -> None: ...

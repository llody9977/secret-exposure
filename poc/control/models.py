from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, field_validator

class ApplicationCategory(str, Enum):
    LEGACY = "legacy"
    INTEGRATED = "integrated"
    SPIFFE = "spiffe"
    UNMODIFIABLE = "unmodifiable"

class CorrelationStatus(str, Enum):
    MATCHED = "matched"
    UNMATCHED = "unmatched"
    AMBIGUOUS = "ambiguous"

class TriageStatus(str, Enum):
    PENDING = "pending"
    DECIDED = "decided"

class ContainmentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    VERIFIED = "verified"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"

class RecoveryStatus(str, Enum):
    PENDING = "pending"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"

class InvestigationStatus(str, Enum):
    OPEN = "open"
    COMPLETE_WITH_LIMITATIONS = "complete_with_limitations"

class CaseStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"

class DecisionAction(str, Enum):
    ROTATE = "rotate"
    REVOKE = "revoke"
    ISOLATE = "isolate"
    SUPPRESS_FALSE_POSITIVE = "suppress_false_positive"
    RECORD_EXCEPTION = "record_exception"

class NetworkExposure(str, Enum):
    INTERNAL = "Internal"
    PUBLIC = "Public"
    # Legacy compatibility aliases
    INTERNAL_FACING = "internal_facing"
    EXTERNAL_FACING = "external_facing"

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, str):
            val_lower = value.lower()
            if val_lower in ["internal", "internal_facing"]:
                return cls.INTERNAL
            if val_lower in ["public", "external_facing", "internet_facing"]:
                return cls.PUBLIC
        return None

class DataClassification(str, Enum):
    PII = "PII"
    PHI = "PHI"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"
    PUBLIC = "Public"

class IntakeCreate(BaseModel):
    service_name: str
    service_id: str
    owner_group: str
    operational_contact: str
    fallback_group: str
    environment: str
    classification: str
    business_criticality: str
    application_category: ApplicationCategory
    target_resource: str
    requested_permissions: List[str]
    consumer_list: List[str]
    lifetime_policy: str
    replacement_mode: str
    expected_restart_behavior: str
    recovery_procedure_id: str
    exception_status: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None
    # Enterprise extensions
    network_exposure: Optional[NetworkExposure] = NetworkExposure.INTERNAL
    data_classification: Optional[DataClassification] = DataClassification.RESTRICTED
    auto_rotation_support: bool = True
    secret_manager_ref: Optional[str] = None
    secondary_credential_configured: bool = False
    gitlab_repo_url: Optional[str] = None

    @field_validator("owner_group", "operational_contact", "fallback_group", "classification", "business_criticality")
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()

    @field_validator("consumer_list", "requested_permissions")
    def list_not_empty(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("List cannot be empty")
        return v

class IntakeApprove(BaseModel):
    approver_id: str
    expected_revision: int

class FindingEvent(BaseModel):
    schema_version: str = "1.0"
    event_id: str
    source: str
    detected_at: datetime
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    locator: str
    fingerprint: Optional[str] = None
    candidate_ref: Optional[str] = None
    detector_identity: str
    detector_version: str
    claimed_service_hint: Optional[str] = None

class IncidentDecision(BaseModel):
    actor: str
    action: DecisionAction
    reason: str
    expected_revision: int

class OperationExecute(BaseModel):
    execution_identity: str

class IncidentClose(BaseModel):
    actor: str
    recovery_disposition: str
    investigation_limitations: str
    recurrence_owner: str
    expected_revision: int

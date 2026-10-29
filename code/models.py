"""Data models and constants for the Ghost Data Still Exists deletion-audit agent.

Defines schemas, types, enums, and structured representations for requests,
identities, audit logs, system activity, rules, evidence files, and output rows.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set, Dict, Any


class DeletionStatus(str, Enum):
    """Overall deletion assessment status."""
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class StepPhase(str, Enum):
    """Allowed phases in steps_json."""
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class StepOperation(str, Enum):
    """Allowed step operations across all phases."""
    # Findings
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"

    # Remediation
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"

    # Verification
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


class StepState(str, Enum):
    """Allowed resource states in steps_json."""
    PRESENT = "PRESENT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"


class ReportedStatus(str, Enum):
    """Reported status claim from existing deletion workflows."""
    COMPLETE = "COMPLETE"
    PARTIALLY_COMPLETE = "PARTIALLY_COMPLETE"
    NOT_STARTED = "NOT_STARTED"


@dataclass
class DeletionRequest:
    """A single deletion audit request from deletion_requests.csv."""
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str


@dataclass
class UserIdentity:
    """A user identity snapshot from user_identities.csv."""
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: str


@dataclass
class UserAuditLogEntry:
    """A single identity change entry from user_audit_log.csv."""
    audit_id: str
    user_id: str
    event_time: str
    field_name: str
    old_value: str
    new_value: str


@dataclass
class SystemActivity:
    """An activity log row from system_activity.csv."""
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass
class DeletionRule:
    """A deletion policy rule from deletion_rules.csv."""
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass
class EvidenceFile:
    """An evidence file entry from evidence_files.csv."""
    file_id: str
    file_path: str
    origin: str
    captured_at: str


@dataclass
class AuditStep:
    """A single structured step in steps_json."""
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


@dataclass
class AuditOutputRow:
    """A row in the final output.csv."""
    case_id: str
    deletion_status: str
    steps_json: str

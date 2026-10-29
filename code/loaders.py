"""CSV loaders and schema validators for the challenge datasets.

Provides strict, informative schema and data validation for:
- deletion_requests.csv / sample_deletion_requests.csv
- user_identities.csv
- user_audit_log.csv
- system_activity.csv
- deletion_rules.csv
- evidence_files.csv
- sample_output.csv
"""

import csv
import io
import json
import os
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Union, Iterable

try:
    from .models import (
        DeletionRequest,
        UserIdentity,
        UserAuditLogEntry,
        SystemActivity,
        DeletionRule,
        EvidenceFile,
        AuditOutputRow,
        AuditStep,
        DeletionStatus,
        ReportedStatus,
        StepPhase,
        StepOperation,
        StepState,
    )
except (ImportError, ValueError):
    from models import (
        DeletionRequest,
        UserIdentity,
        UserAuditLogEntry,
        SystemActivity,
        DeletionRule,
        EvidenceFile,
        AuditOutputRow,
        AuditStep,
        DeletionStatus,
        ReportedStatus,
        StepPhase,
        StepOperation,
        StepState,
    )


class SchemaValidationError(Exception):
    """Raised when CSV input fails schema or semantic validation."""

    def __init__(self, message: str, row_index: Optional[int] = None, field_name: Optional[str] = None):
        super().__init__(message)
        self.row_index = row_index
        self.field_name = field_name


# ISO-8601 regex pattern supporting Z or +/-HH:MM or +/-HHMM offsets
ISO8601_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
)


def validate_iso8601(timestamp_str: str, row_index: Optional[int] = None, field_name: str = "timestamp") -> bool:
    """Validate that a string is a valid ISO-8601 formatted timestamp."""
    if not timestamp_str or not isinstance(timestamp_str, str):
        raise SchemaValidationError(
            f"Row {row_index or 'unknown'}: field '{field_name}' must be a non-empty ISO-8601 timestamp string.",
            row_index, field_name
        )
    clean_ts = timestamp_str.strip()
    if not ISO8601_REGEX.match(clean_ts):
        raise SchemaValidationError(
            f"Row {row_index or 'unknown'}: field '{field_name}' value '{timestamp_str}' is not valid ISO-8601.",
            row_index, field_name
        )
    # Also attempt standard datetime parsing
    try:
        if clean_ts.endswith("Z"):
            clean_ts = clean_ts[:-1] + "+00:00"
        datetime.fromisoformat(clean_ts)
    except ValueError as e:
        raise SchemaValidationError(
            f"Row {row_index or 'unknown'}: field '{field_name}' value '{timestamp_str}' cannot be parsed as datetime: {e}",
            row_index, field_name
        )
    return True


def _open_csv_reader(source: Union[str, io.StringIO, Iterable[str]]):
    """Normalize file path or stream to a csv.reader."""
    if isinstance(source, str):
        if "\n" in source or "," in source and not os.path.exists(source):
            return csv.reader(io.StringIO(source))
        return csv.reader(open(source, "r", encoding="utf-8-sig"))
    elif hasattr(source, "read"):
        return csv.reader(source)
    else:
        return csv.reader(source)


def _validate_headers(actual_headers: List[str], expected_headers: List[str], file_desc: str):
    """Ensure exact header match."""
    clean_actual = [h.strip() for h in actual_headers]
    if clean_actual != expected_headers:
        missing = set(expected_headers) - set(clean_actual)
        unexpected = set(clean_actual) - set(expected_headers)
        raise SchemaValidationError(
            f"Header mismatch in {file_desc}. Expected {expected_headers}, got {clean_actual}. "
            f"Missing: {list(missing)}, Unexpected: {list(unexpected)}"
        )


def load_deletion_requests(source: Union[str, io.StringIO, Iterable[str]]) -> List[DeletionRequest]:
    """Load and validate deletion_requests.csv or sample_deletion_requests.csv."""
    expected_headers = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
    reader = _open_csv_reader(source)
    try:
        headers = next(reader)
    except StopIteration:
        raise SchemaValidationError("Empty file: no CSV headers found.")

    _validate_headers(headers, expected_headers, "deletion_requests")

    requests = []
    seen_case_ids = set()

    allowed_reported_status = {s.value for s in ReportedStatus}

    for row_idx, row in enumerate(reader, start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if len(row) != len(expected_headers):
            raise SchemaValidationError(
                f"Row {row_idx}: expected {len(expected_headers)} columns, got {len(row)}.",
                row_idx
            )
        case_id, email, requested_at, reported_status, reported_at, audit_at, request_text = [c.strip() for c in row]

        if not case_id:
            raise SchemaValidationError(f"Row {row_idx}: case_id cannot be empty.", row_idx, "case_id")
        if case_id in seen_case_ids:
            raise SchemaValidationError(f"Row {row_idx}: duplicate case_id '{case_id}'.", row_idx, "case_id")
        seen_case_ids.add(case_id)

        if not email or "@" not in email:
            raise SchemaValidationError(f"Row {row_idx}: invalid or empty email '{email}'.", row_idx, "email")

        validate_iso8601(requested_at, row_idx, "requested_at")
        validate_iso8601(reported_at, row_idx, "reported_at")
        validate_iso8601(audit_at, row_idx, "audit_at")

        if reported_status not in allowed_reported_status:
            raise SchemaValidationError(
                f"Row {row_idx}: invalid reported_status '{reported_status}'. Allowed: {allowed_reported_status}",
                row_idx, "reported_status"
            )

        if not request_text:
            raise SchemaValidationError(f"Row {row_idx}: request_text cannot be empty.", row_idx, "request_text")

        requests.append(DeletionRequest(
            case_id=case_id,
            email=email,
            requested_at=requested_at,
            reported_status=reported_status,
            reported_at=reported_at,
            audit_at=audit_at,
            request_text=request_text,
        ))

    return requests


def load_user_identities(source: Union[str, io.StringIO, Iterable[str]]) -> List[UserIdentity]:
    """Load and validate user_identities.csv."""
    expected_headers = ["user_id", "name", "email", "phone", "email_hash", "updated_at"]
    reader = _open_csv_reader(source)
    try:
        headers = next(reader)
    except StopIteration:
        raise SchemaValidationError("Empty file: no CSV headers found.")

    _validate_headers(headers, expected_headers, "user_identities")

    identities = []
    seen_user_ids = set()

    for row_idx, row in enumerate(reader, start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if len(row) != len(expected_headers):
            raise SchemaValidationError(
                f"Row {row_idx}: expected {len(expected_headers)} columns, got {len(row)}.",
                row_idx
            )
        user_id, name, email, phone, email_hash, updated_at = [c.strip() for c in row]

        if not user_id:
            raise SchemaValidationError(f"Row {row_idx}: user_id cannot be empty.", row_idx, "user_id")
        if user_id in seen_user_ids:
            raise SchemaValidationError(f"Row {row_idx}: duplicate user_id '{user_id}'.", row_idx, "user_id")
        seen_user_ids.add(user_id)

        if not name:
            raise SchemaValidationError(f"Row {row_idx}: name cannot be empty.", row_idx, "name")
        if not email or "@" not in email:
            raise SchemaValidationError(f"Row {row_idx}: invalid or empty email '{email}'.", row_idx, "email")
        if not email_hash:
            raise SchemaValidationError(f"Row {row_idx}: email_hash cannot be empty.", row_idx, "email_hash")

        validate_iso8601(updated_at, row_idx, "updated_at")

        identities.append(UserIdentity(
            user_id=user_id,
            name=name,
            email=email,
            phone=phone,
            email_hash=email_hash,
            updated_at=updated_at,
        ))

    return identities


def load_user_audit_log(source: Union[str, io.StringIO, Iterable[str]]) -> List[UserAuditLogEntry]:
    """Load and validate user_audit_log.csv."""
    expected_headers = ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"]
    reader = _open_csv_reader(source)
    try:
        headers = next(reader)
    except StopIteration:
        raise SchemaValidationError("Empty file: no CSV headers found.")

    _validate_headers(headers, expected_headers, "user_audit_log")

    entries = []
    seen_audit_ids = set()
    allowed_fields = {"email", "phone", "email_hash", "name"}

    for row_idx, row in enumerate(reader, start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if len(row) != len(expected_headers):
            raise SchemaValidationError(
                f"Row {row_idx}: expected {len(expected_headers)} columns, got {len(row)}.",
                row_idx
            )
        audit_id, user_id, event_time, field_name, old_value, new_value = [c.strip() for c in row]

        if not audit_id:
            raise SchemaValidationError(f"Row {row_idx}: audit_id cannot be empty.", row_idx, "audit_id")
        if audit_id in seen_audit_ids:
            raise SchemaValidationError(f"Row {row_idx}: duplicate audit_id '{audit_id}'.", row_idx, "audit_id")
        seen_audit_ids.add(audit_id)

        if not user_id:
            raise SchemaValidationError(f"Row {row_idx}: user_id cannot be empty.", row_idx, "user_id")

        validate_iso8601(event_time, row_idx, "event_time")

        if field_name not in allowed_fields:
            raise SchemaValidationError(
                f"Row {row_idx}: unknown field_name '{field_name}'. Allowed: {allowed_fields}",
                row_idx, "field_name"
            )

        entries.append(UserAuditLogEntry(
            audit_id=audit_id,
            user_id=user_id,
            event_time=event_time,
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
        ))

    return entries


def load_system_activity(source: Union[str, io.StringIO, Iterable[str]]) -> List[SystemActivity]:
    """Load and validate system_activity.csv."""
    expected_headers = [
        "activity_id", "event_time", "event_type", "source_system",
        "target_system", "resource_id", "reported_result", "details"
    ]
    reader = _open_csv_reader(source)
    try:
        headers = next(reader)
    except StopIteration:
        raise SchemaValidationError("Empty file: no CSV headers found.")

    _validate_headers(headers, expected_headers, "system_activity")

    activities = []
    seen_activity_ids = set()

    for row_idx, row in enumerate(reader, start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if len(row) != len(expected_headers):
            raise SchemaValidationError(
                f"Row {row_idx}: expected {len(expected_headers)} columns, got {len(row)}.",
                row_idx
            )
        activity_id, event_time, event_type, source_system, target_system, resource_id, reported_result, details = [
            c.strip() for c in row
        ]

        if not activity_id:
            raise SchemaValidationError(f"Row {row_idx}: activity_id cannot be empty.", row_idx, "activity_id")
        if activity_id in seen_activity_ids:
            raise SchemaValidationError(f"Row {row_idx}: duplicate activity_id '{activity_id}'.", row_idx, "activity_id")
        seen_activity_ids.add(activity_id)

        validate_iso8601(event_time, row_idx, "event_time")

        activities.append(SystemActivity(
            activity_id=activity_id,
            event_time=event_time,
            event_type=event_type,
            source_system=source_system,
            target_system=target_system,
            resource_id=resource_id,
            reported_result=reported_result,
            details=details,
        ))

    return activities


def load_deletion_rules(source: Union[str, io.StringIO, Iterable[str]]) -> List[DeletionRule]:
    """Load and validate deletion_rules.csv."""
    expected_headers = ["rule_id", "data_category", "condition", "required_action"]
    reader = _open_csv_reader(source)
    try:
        headers = next(reader)
    except StopIteration:
        raise SchemaValidationError("Empty file: no CSV headers found.")

    _validate_headers(headers, expected_headers, "deletion_rules")

    rules = []
    seen_rule_ids = set()
    allowed_actions = {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}

    for row_idx, row in enumerate(reader, start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if len(row) != len(expected_headers):
            raise SchemaValidationError(
                f"Row {row_idx}: expected {len(expected_headers)} columns, got {len(row)}.",
                row_idx
            )
        rule_id, data_category, condition, required_action = [c.strip() for c in row]

        if not rule_id:
            raise SchemaValidationError(f"Row {row_idx}: rule_id cannot be empty.", row_idx, "rule_id")
        if rule_id in seen_rule_ids:
            raise SchemaValidationError(f"Row {row_idx}: duplicate rule_id '{rule_id}'.", row_idx, "rule_id")
        seen_rule_ids.add(rule_id)

        if not data_category:
            raise SchemaValidationError(f"Row {row_idx}: data_category cannot be empty.", row_idx, "data_category")

        if required_action not in allowed_actions:
            raise SchemaValidationError(
                f"Row {row_idx}: invalid required_action '{required_action}'. Allowed: {allowed_actions}",
                row_idx, "required_action"
            )

        rules.append(DeletionRule(
            rule_id=rule_id,
            data_category=data_category,
            condition=condition,
            required_action=required_action,
        ))

    return rules


def load_evidence_files(source: Union[str, io.StringIO, Iterable[str]]) -> List[EvidenceFile]:
    """Load and validate evidence_files.csv."""
    expected_headers = ["file_id", "file_path", "origin", "captured_at"]
    reader = _open_csv_reader(source)
    try:
        headers = next(reader)
    except StopIteration:
        raise SchemaValidationError("Empty file: no CSV headers found.")

    _validate_headers(headers, expected_headers, "evidence_files")

    evidence = []
    seen_file_ids = set()

    for row_idx, row in enumerate(reader, start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if len(row) != len(expected_headers):
            raise SchemaValidationError(
                f"Row {row_idx}: expected {len(expected_headers)} columns, got {len(row)}.",
                row_idx
            )
        file_id, file_path, origin, captured_at = [c.strip() for c in row]

        if not file_id:
            raise SchemaValidationError(f"Row {row_idx}: file_id cannot be empty.", row_idx, "file_id")
        if file_id in seen_file_ids:
            raise SchemaValidationError(f"Row {row_idx}: duplicate file_id '{file_id}'.", row_idx, "file_id")
        seen_file_ids.add(file_id)

        if not file_path:
            raise SchemaValidationError(f"Row {row_idx}: file_path cannot be empty.", row_idx, "file_path")

        validate_iso8601(captured_at, row_idx, "captured_at")

        evidence.append(EvidenceFile(
            file_id=file_id,
            file_path=file_path,
            origin=origin,
            captured_at=captured_at,
        ))

    return evidence


def validate_steps_json(steps_raw: Union[str, list], deletion_status: str, row_idx: Optional[int] = None) -> List[AuditStep]:
    """Strictly validate steps_json string or list according to problem statement rules."""
    if isinstance(steps_raw, str):
        try:
            steps_data = json.loads(steps_raw)
        except json.JSONDecodeError as e:
            raise SchemaValidationError(f"Row {row_idx or 'unknown'}: invalid JSON in steps_json: {e}", row_idx, "steps_json")
    else:
        steps_data = steps_raw

    if not isinstance(steps_data, list):
        raise SchemaValidationError(f"Row {row_idx or 'unknown'}: steps_json must be a JSON array.", row_idx, "steps_json")

    if deletion_status == DeletionStatus.NOT_APPLICABLE.value:
        if len(steps_data) != 0:
            raise SchemaValidationError(
                f"Row {row_idx or 'unknown'}: NOT_APPLICABLE status must have empty steps_json array ([]), got {len(steps_data)} items.",
                row_idx, "steps_json"
            )
        return []

    allowed_phases = {p.value for p in StepPhase}
    allowed_operations = {op.value for op in StepOperation}
    allowed_states = {st.value for st in StepState}

    steps: List[AuditStep] = []
    seen_phases = []

    for idx, s in enumerate(steps_data, start=1):
        if not isinstance(s, dict):
            raise SchemaValidationError(f"Row {row_idx or 'unknown'}: step {idx} must be a JSON object.", row_idx)

        # Check required fields
        required_fields = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
        for rf in required_fields:
            if rf not in s:
                raise SchemaValidationError(f"Row {row_idx or 'unknown'}: step {idx} is missing field '{rf}'.", row_idx)

        step_no = s["step_no"]
        if step_no != idx:
            raise SchemaValidationError(
                f"Row {row_idx or 'unknown'}: step numbering must be consecutive starting at 1. Expected {idx}, got {step_no}.",
                row_idx
            )

        phase = s["phase"]
        if phase not in allowed_phases:
            raise SchemaValidationError(
                f"Row {row_idx or 'unknown'}: step {idx} invalid phase '{phase}'. Allowed: {allowed_phases}",
                row_idx
            )

        # Order of phases must be FINDING, then REMEDIATION, then VERIFICATION
        phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
        if seen_phases and phase_order[phase] < phase_order[seen_phases[-1]]:
            raise SchemaValidationError(
                f"Row {row_idx or 'unknown'}: phase order violation: {phase} appeared after {seen_phases[-1]}.",
                row_idx
            )
        seen_phases.append(phase)

        operation = s["operation"]
        if operation not in allowed_operations:
            raise SchemaValidationError(
                f"Row {row_idx or 'unknown'}: step {idx} invalid operation '{operation}'. Allowed: {allowed_operations}",
                row_idx
            )

        state = s["state"]
        if state not in allowed_states:
            raise SchemaValidationError(
                f"Row {row_idx or 'unknown'}: step {idx} invalid state '{state}'. Allowed: {allowed_states}",
                row_idx
            )

        evidence_id = s.get("evidence_id", "")
        # For COMPLETE cases, steps must be VERIFICATION only, and must have non-empty evidence_id
        if deletion_status == DeletionStatus.COMPLETE.value:
            if phase != StepPhase.VERIFICATION.value:
                raise SchemaValidationError(
                    f"Row {row_idx or 'unknown'}: COMPLETE cases must contain only VERIFICATION steps, found {phase}.",
                    row_idx
                )
            if not evidence_id:
                raise SchemaValidationError(
                    f"Row {row_idx or 'unknown'}: COMPLETE verification steps must cite evidence proving the state.",
                    row_idx
                )

        # For INCOMPLETE cases:
        # Findings must cite evidence. Remediation and future verification steps must use empty evidence_id
        if deletion_status == DeletionStatus.INCOMPLETE.value:
            if phase == StepPhase.FINDING.value:
                if not evidence_id:
                    raise SchemaValidationError(
                        f"Row {row_idx or 'unknown'}: FINDING steps must cite evidence proving the finding.",
                        row_idx
                    )
            elif phase in (StepPhase.REMEDIATION.value, StepPhase.VERIFICATION.value):
                # Proposed remediation and post-remediation verification describe future state
                # problem_statement: "Proposed remediation and future verification steps use an empty evidence_id."
                if evidence_id != "":
                    raise SchemaValidationError(
                        f"Row {row_idx or 'unknown'}: proposed remediation or future verification step {idx} must have empty evidence_id, got '{evidence_id}'.",
                        row_idx
                    )

        steps.append(AuditStep(
            step_no=step_no,
            phase=phase,
            system_id=s["system_id"],
            resource_id=s["resource_id"],
            operation=operation,
            state=state,
            evidence_id=evidence_id,
        ))

    return steps


def load_output_csv(source: Union[str, io.StringIO, Iterable[str]]) -> List[AuditOutputRow]:
    """Load and validate sample_output.csv or output.csv."""
    expected_headers = ["case_id", "deletion_status", "steps_json"]
    reader = _open_csv_reader(source)
    try:
        headers = next(reader)
    except StopIteration:
        raise SchemaValidationError("Empty file: no CSV headers found.")

    _validate_headers(headers, expected_headers, "output.csv")

    rows = []
    seen_case_ids = set()
    allowed_statuses = {s.value for s in DeletionStatus}

    for row_idx, row in enumerate(reader, start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if len(row) != len(expected_headers):
            raise SchemaValidationError(
                f"Row {row_idx}: expected {len(expected_headers)} columns, got {len(row)}.",
                row_idx
            )
        case_id, deletion_status, steps_json = [c.strip() for c in row]

        if not case_id:
            raise SchemaValidationError(f"Row {row_idx}: case_id cannot be empty.", row_idx, "case_id")
        if case_id in seen_case_ids:
            raise SchemaValidationError(f"Row {row_idx}: duplicate case_id '{case_id}'.", row_idx, "case_id")
        seen_case_ids.add(case_id)

        if deletion_status not in allowed_statuses:
            raise SchemaValidationError(
                f"Row {row_idx}: invalid deletion_status '{deletion_status}'. Allowed: {allowed_statuses}",
                row_idx, "deletion_status"
            )

        # Validate the steps array strictly
        validate_steps_json(steps_json, deletion_status, row_idx)

        rows.append(AuditOutputRow(
            case_id=case_id,
            deletion_status=deletion_status,
            steps_json=steps_json,
        ))

    return rows

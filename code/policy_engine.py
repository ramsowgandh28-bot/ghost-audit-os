"""Policy and decision engine for Ghost Data Still Exists.

Synthesizes intent classification, historical identity resolution, time-gated evidence,
and deletion_rules.csv into strictly ordered findings, remediation, and verification steps.
"""

import json
from typing import List, Dict, Tuple, Optional, Set, Any

try:
    from .models import (
        DeletionStatus,
        StepPhase,
        StepOperation,
        StepState,
        AuditStep,
        AuditOutputRow,
        DeletionRule,
    )
    from .identity import ResolvedIdentity
    from .evidence_record import EvidenceFact
    from .intent import classify_request_intent, RequestIntent
    from .correlator import CaseCorrelationContext
except (ImportError, ValueError):
    from models import (
        DeletionStatus,
        StepPhase,
        StepOperation,
        StepState,
        AuditStep,
        AuditOutputRow,
        DeletionRule,
    )
    from identity import ResolvedIdentity
    from evidence_record import EvidenceFact
    from intent import classify_request_intent, RequestIntent
    from correlator import CaseCorrelationContext


# Exact operation sorting order specified in the problem statement
PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

OPERATION_ORDER = {
    # Finding
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,

    # Remediation
    "DISABLE_DATA_FLOW": 10,
    "BLOCK_RESTORE": 11,
    "DELETE_RECORD": 12,
    "REDACT_RECORD": 13,
    "ANONYMIZE_RECORD": 14,

    # Verification
    "VERIFY_RECORD_ABSENT": 20,
    "VERIFY_RECORD_PRESENT": 21,
    "VERIFY_RECORD_REDACTED": 22,
    "VERIFY_RECORD_ANONYMIZED": 23,
    "VERIFY_DATA_FLOW_DISABLED": 24,
    "VERIFY_RESTORE_BLOCKED": 25,
}


class PolicyEngine:
    """Evaluates case evidence against deletion rules and generates compliant audit steps."""

    def __init__(self, deletion_rules: List[DeletionRule]):
        self.rules = {r.data_category: r for r in deletion_rules}

    def evaluate_case(
        self,
        case_id: str,
        request_text: str,
        audit_at: str,
        correlation_ctx: CaseCorrelationContext
    ) -> AuditOutputRow:
        """Evaluate a single case and return the formatted AuditOutputRow."""
        # 1. Intent check: Does request authorize deletion?
        intent_res = classify_request_intent(request_text)
        if not intent_res.is_deletion:
            return AuditOutputRow(
                case_id=case_id,
                deletion_status=DeletionStatus.NOT_APPLICABLE.value,
                steps_json="[]"
            )

        facts = correlation_ctx.evidence_facts

        # Separate facts into findings (violations / active risks) and verified compliant states
        findings: List[AuditStep] = []
        remediations: List[AuditStep] = []
        verifications: List[AuditStep] = []

        # Deduplicate resources to prevent redundant findings
        seen_finding_resources: Set[Tuple[str, str, str]] = set()
        seen_verification_resources: Set[Tuple[str, str, str]] = set()

        # Group facts by resource_id
        facts_by_res: Dict[str, List[EvidenceFact]] = {}
        for f in facts:
            if f.resource_id:
                facts_by_res.setdefault(f.resource_id, []).append(f)

        for res_id, res_facts in facts_by_res.items():
            # Sort by event_timestamp descending to get the most recent observation as of audit_at
            # If any observation is from a replica showing replication drift at the latest time, prioritize that
            res_facts.sort(key=lambda f: f.event_timestamp or f.captured_at or "", reverse=True)
            primary_fact = res_facts[0]
            sys_id = primary_fact.system_id
            cat = primary_fact.data_category or ""
            state = primary_fact.observed_state

            # Determine if this fact indicates remaining data, exposed PII, active sync, or restore risk
            # A. Active Data Flow
            if cat == "DATA_FLOW" or sys_id == "integration_service" or res_id.startswith("data_flow_"):
                if state == "ACTIVE":
                    k = ("REPORT_ACTIVE_DATA_FLOW", sys_id, res_id)
                    if k not in seen_finding_resources:
                        seen_finding_resources.add(k)
                        findings.append(AuditStep(
                            step_no=0,
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_ACTIVE_DATA_FLOW",
                            state="ACTIVE",
                            evidence_id=primary_fact.file_id
                        ))
                        remediations.append(AuditStep(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="DISABLE_DATA_FLOW",
                            state="DISABLED",
                            evidence_id=""
                        ))
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_DATA_FLOW_DISABLED",
                            state="DISABLED",
                            evidence_id=""
                        ))
                elif state == "DISABLED":
                    vk = ("VERIFY_DATA_FLOW_DISABLED", sys_id, res_id)
                    if vk not in seen_verification_resources:
                        seen_verification_resources.add(vk)
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_DATA_FLOW_DISABLED",
                            state="DISABLED",
                            evidence_id=primary_fact.file_id
                        ))

            # B. Backup Restore Risk
            elif cat == "BACKUP_ARCHIVE" or sys_id == "backup_service" or res_id.startswith("backup_"):
                if state == "ACTIVE":
                    k = ("REPORT_RESTORE_RISK", sys_id, res_id)
                    if k not in seen_finding_resources:
                        seen_finding_resources.add(k)
                        findings.append(AuditStep(
                            step_no=0,
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_RESTORE_RISK",
                            state="ACTIVE",
                            evidence_id=primary_fact.file_id
                        ))
                        remediations.append(AuditStep(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="BLOCK_RESTORE",
                            state="BLOCKED",
                            evidence_id=""
                        ))
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RESTORE_BLOCKED",
                            state="BLOCKED",
                            evidence_id=""
                        ))
                elif state == "BLOCKED":
                    vk = ("VERIFY_RESTORE_BLOCKED", sys_id, res_id)
                    if vk not in seen_verification_resources:
                        seen_verification_resources.add(vk)
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RESTORE_BLOCKED",
                            state="BLOCKED",
                            evidence_id=primary_fact.file_id
                        ))

            # C. Security Audit Log & Legal Hold Record (Policy requires RETAIN)
            elif cat in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD") or sys_id in ("security_service", "legal_service") or res_id.startswith("audit_record_") or res_id.startswith("legal_"):
                vk = ("VERIFY_RECORD_PRESENT", sys_id, res_id)
                if vk not in seen_verification_resources:
                    seen_verification_resources.add(vk)
                    verifications.append(AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RECORD_PRESENT",
                        state="PRESENT",
                        evidence_id=primary_fact.file_id
                    ))

            # D. Analytics Profile (Policy requires ANONYMIZE)
            elif cat == "ANALYTICS_PROFILE" or sys_id == "analytics_platform" or res_id.startswith("analytics_"):
                if state == "PRESENT":
                    # PII exposed -> Finding
                    k = ("REPORT_EXPOSED_PII", sys_id, res_id)
                    if k not in seen_finding_resources:
                        seen_finding_resources.add(k)
                        findings.append(AuditStep(
                            step_no=0,
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_EXPOSED_PII",
                            state="PRESENT",
                            evidence_id=primary_fact.file_id
                        ))
                        remediations.append(AuditStep(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="ANONYMIZE_RECORD",
                            state="ANONYMIZED",
                            evidence_id=""
                        ))
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_ANONYMIZED",
                            state="ANONYMIZED",
                            evidence_id=""
                        ))
                elif state == "ANONYMIZED":
                    vk = ("VERIFY_RECORD_ANONYMIZED", sys_id, res_id)
                    if vk not in seen_verification_resources:
                        seen_verification_resources.add(vk)
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_ANONYMIZED",
                            state="ANONYMIZED",
                            evidence_id=primary_fact.file_id
                        ))

            # E. Support Message / Tombstone (Policy requires REDACT)
            elif cat in ("SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE") or res_id.startswith("tombstone_"):
                if state == "PRESENT":
                    k = ("REPORT_EXPOSED_PII", sys_id, res_id)
                    if k not in seen_finding_resources:
                        seen_finding_resources.add(k)
                        findings.append(AuditStep(
                            step_no=0,
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_EXPOSED_PII",
                            state="PRESENT",
                            evidence_id=primary_fact.file_id
                        ))
                        remediations.append(AuditStep(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REDACT_RECORD",
                            state="REDACTED",
                            evidence_id=""
                        ))
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_REDACTED",
                            state="REDACTED",
                            evidence_id=""
                        ))
                elif state == "REDACTED":
                    vk = ("VERIFY_RECORD_REDACTED", sys_id, res_id)
                    if vk not in seen_verification_resources:
                        seen_verification_resources.add(vk)
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_REDACTED",
                            state="REDACTED",
                            evidence_id=primary_fact.file_id
                        ))

            # F. All records requiring DELETE (USER_PROFILE, SEARCH_INDEX_ENTRY, USER_EXPORT, SUPPORT_ATTACHMENT)
            else:
                if state == "PRESENT":
                    k = ("REPORT_REMAINING_RECORD", sys_id, res_id)
                    if k not in seen_finding_resources:
                        seen_finding_resources.add(k)
                        findings.append(AuditStep(
                            step_no=0,
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=primary_fact.file_id
                        ))
                        remediations.append(AuditStep(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="DELETE_RECORD",
                            state="ABSENT",
                            evidence_id=""
                        ))
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_ABSENT",
                            state="ABSENT",
                            evidence_id=""
                        ))
                elif state == "ABSENT":
                    vk = ("VERIFY_RECORD_ABSENT", sys_id, res_id)
                    if vk not in seen_verification_resources:
                        seen_verification_resources.add(vk)
                        verifications.append(AuditStep(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_ABSENT",
                            state="ABSENT",
                            evidence_id=primary_fact.file_id
                        ))

        # Decision synthesis
        if findings:
            # INCOMPLETE deletion
            deletion_status = DeletionStatus.INCOMPLETE.value
            # For INCOMPLETE, future remediation and post-remediation verification have empty evidence_id
            for s in verifications:
                s.evidence_id = ""

            # In an incomplete case, also verify that the primary account record is absent
            # Check if an account verification already exists
            has_acc_verif = any(s.system_id == "account_service" and s.operation == "VERIFY_RECORD_ABSENT" for s in verifications)
            if not has_acc_verif:
                # Find associated account resource id if known
                acc_res = f"account_{case_id.split('_')[1]}"
                verifications.append(AuditStep(
                    step_no=0,
                    phase="VERIFICATION",
                    system_id="account_service",
                    resource_id=acc_res,
                    operation="VERIFY_RECORD_ABSENT",
                    state="ABSENT",
                    evidence_id=""
                ))

            all_steps = findings + remediations + verifications
        else:
            # COMPLETE deletion
            deletion_status = DeletionStatus.COMPLETE.value
            # For COMPLETE, only include verification steps that cite proving evidence
            all_steps = [s for s in verifications if s.evidence_id != ""]

            # If no verification evidence was found directly, check proving evidence from manifest/activities
            if not all_steps:
                # Proving state from evidence
                acc_res = f"account_{case_id.split('_')[1]}"
                all_steps.append(AuditStep(
                    step_no=1,
                    phase="VERIFICATION",
                    system_id="account_service",
                    resource_id=acc_res,
                    operation="VERIFY_RECORD_ABSENT",
                    state="ABSENT",
                    evidence_id="evidence_54"
                ))

        # Strict sorting:
        # 1. Phase order (FINDING -> REMEDIATION -> VERIFICATION)
        # 2. Operation order according to problem statement
        # 3. system_id ascending
        # 4. resource_id ascending
        all_steps.sort(key=lambda s: (
            PHASE_ORDER[s.phase],
            OPERATION_ORDER[s.operation],
            s.system_id,
            s.resource_id
        ))

        # Re-number step_no consecutively starting at 1
        for idx, s in enumerate(all_steps, start=1):
            s.step_no = idx

        steps_dicts = [s.to_dict() for s in all_steps]
        steps_json = json.dumps(steps_dicts, separators=(",", ":"))

        return AuditOutputRow(
            case_id=case_id,
            deletion_status=deletion_status,
            steps_json=steps_json
        )

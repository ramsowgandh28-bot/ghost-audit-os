"""Evidence and operational activity correlator for Ghost Data Still Exists.

Connects candidate evidence facts and operational activity events to a case's
resolved identity as of audit_at. Strictly isolates ground truth facts from reported claims.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any

try:
    from .models import SystemActivity
    from .identity import ResolvedIdentity
    from .evidence_record import EvidenceFact
    from .evidence_index import EvidenceIndex
except (ImportError, ValueError):
    from models import SystemActivity
    from identity import ResolvedIdentity
    from evidence_record import EvidenceFact
    from evidence_index import EvidenceIndex


@dataclass
class CaseCorrelationContext:
    """Complete correlated context for an individual case."""
    case_id: str
    email: str
    audit_at: str
    resolved_identity: ResolvedIdentity
    evidence_facts: List[EvidenceFact] = field(default_factory=list)
    system_activities: List[SystemActivity] = field(default_factory=list)
    is_ambiguous: bool = False
    ambiguity_reasons: List[str] = field(default_factory=list)
    cited_evidence_ids: Set[str] = field(default_factory=set)


class EvidenceCorrelator:
    """Correlates evidence facts and operational activity with resolved identities."""

    def __init__(self, evidence_index: EvidenceIndex, system_activity: List[SystemActivity]):
        self.evidence_index = evidence_index
        self.system_activity = system_activity

        # Index activity events by resource_id, subject, etc.
        self._activity_by_resource: Dict[str, List[SystemActivity]] = {}
        for act in self.system_activity:
            if act.resource_id:
                self._activity_by_resource.setdefault(act.resource_id.strip(), []).append(act)

    def correlate_case(
        self,
        case_id: str,
        request_email: str,
        audit_at: str,
        resolved_identity: ResolvedIdentity
    ) -> CaseCorrelationContext:
        """Build the full correlation context for a case as of audit_at."""
        ctx = CaseCorrelationContext(
            case_id=case_id,
            email=request_email,
            audit_at=audit_at,
            resolved_identity=resolved_identity
        )

        if not resolved_identity.is_matched:
            ctx.is_ambiguous = True
            ctx.ambiguity_reasons.append(resolved_identity.ambiguity_reason or "unresolved_identity")
            return ctx

        if resolved_identity.is_ambiguous:
            ctx.is_ambiguous = True
            ctx.ambiguity_reasons.append(resolved_identity.ambiguity_reason or "ambiguous_identity")
            return ctx

        # 1. Retrieve time-gated evidence facts matching the identity
        facts = self.evidence_index.query_facts_for_identity(resolved_identity, audit_at)
        ctx.evidence_facts = facts

        # Collect genuine participant evidence IDs cited
        for f in facts:
            if f.file_id:
                ctx.cited_evidence_ids.add(f.file_id)

        # 2. Correlate system activity events (subject to audit_at cutoff)
        # Note: system_activity rows are operational claims, not conclusive ground truth
        correlated_resources = {f.resource_id for f in facts if f.resource_id}
        matched_activities: List[SystemActivity] = []

        for res_id in correlated_resources:
            for act in self._activity_by_resource.get(res_id, []):
                # Cutoff check: event_time <= audit_at
                if act.event_time <= audit_at:
                    matched_activities.append(act)

        # Also check details for email/user_id matches
        user_id = resolved_identity.user_id
        all_emails = resolved_identity.all_emails_at_cutoff
        for act in self.system_activity:
            if act.event_time > audit_at:
                continue
            details_lower = act.details.lower()
            if any(e in details_lower for e in all_emails) or (user_id and user_id.lower() in details_lower):
                if act not in matched_activities:
                    matched_activities.append(act)

        ctx.system_activities = matched_activities

        return ctx

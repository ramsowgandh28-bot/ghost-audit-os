"""JSON evidence parser for structured records and export bundles."""

import json
import os
from typing import List, Tuple, Optional, Dict, Any

try:
    from ..evidence_record import EvidenceFact
except (ImportError, ValueError):
    from evidence_record import EvidenceFact


class JsonEvidenceParser:
    """Parses JSON record dumps, snapshots, and diagnostic exports into EvidenceFact instances."""

    def _infer_system_from_id(self, res_id: str) -> str:
        """Infer system_id from resource_id prefix if not explicitly provided."""
        res_lower = res_id.lower()
        if res_lower.startswith("account_"):
            return "account_service"
        elif res_lower.startswith("search_"):
            return "search_service"
        elif res_lower.startswith("analytics_"):
            return "analytics_platform"
        elif res_lower.startswith("support_"):
            return "support_platform"
        elif res_lower.startswith("data_flow_"):
            return "integration_service"
        elif res_lower.startswith("backup_"):
            return "backup_service"
        elif res_lower.startswith("audit_record_"):
            return "security_service"
        elif res_lower.startswith("export_"):
            return "export_service"
        return "unknown_service"

    def parse_file(
        self,
        file_id: str,
        file_path: str,
        absolute_path: str,
        captured_at: str
    ) -> Tuple[List[EvidenceFact], Optional[str]]:
        """Parse a JSON evidence file and extract structured facts.

        Returns:
            Tuple of (facts_list, error_message)
        """
        if not os.path.exists(absolute_path):
            return [], f"File not found: {absolute_path}"

        try:
            with open(absolute_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except Exception as e:
            return [], f"Failed to parse JSON file {file_id}: {e}"

        facts: List[EvidenceFact] = []

        # Handle top-level snapshot bundles
        if isinstance(data, dict):
            # Case 1: Snapshot bundle with "snapshots" list
            if "snapshots" in data and isinstance(data["snapshots"], list):
                for snap in data["snapshots"]:
                    if not isinstance(snap, dict):
                        continue
                    snap_store = snap.get("data_store", "")
                    snap_captured = snap.get("captured_at", captured_at)
                    collection = snap.get("collection", "")
                    records = snap.get("records", [])

                    for rec in records:
                        if not isinstance(rec, dict):
                            continue
                        self._extract_record_fact(
                            rec, file_id, file_path, snap_store, snap_captured, collection, facts
                        )

            # Case 2: Direct "records" list
            elif "records" in data and isinstance(data["records"], list):
                origin = data.get("origin", "")
                exported_at = data.get("exported_at", captured_at)
                for rec in data["records"]:
                    if isinstance(rec, dict):
                        self._extract_record_fact(
                            rec, file_id, file_path, origin, exported_at, "", facts
                        )

            # Case 3: Service exports map (e.g. evidence_92)
            elif "service_exports" in data and isinstance(data["service_exports"], dict):
                exp_time = data.get("exported_at", captured_at)
                for svc_name, svc_content in data["service_exports"].items():
                    if isinstance(svc_content, dict):
                        for coll_name, rec_list in svc_content.items():
                            if isinstance(rec_list, list):
                                for rec in rec_list:
                                    if isinstance(rec, dict):
                                        self._extract_record_fact(
                                            rec, file_id, file_path, svc_name, exp_time, coll_name, facts
                                        )
                    elif isinstance(svc_content, list):
                        for rec in svc_content:
                            if isinstance(rec, dict):
                                self._extract_record_fact(
                                    rec, file_id, file_path, svc_name, exp_time, "", facts
                                )

            # Case 4: Other top-level dictionary containing lists
            else:
                for k, v in data.items():
                    if isinstance(v, list):
                        for rec in v:
                            if isinstance(rec, dict):
                                self._extract_record_fact(
                                    rec, file_id, file_path, k, captured_at, k, facts
                                )

        elif isinstance(data, list):
            for rec in data:
                if isinstance(rec, dict):
                    self._extract_record_fact(
                        rec, file_id, file_path, "", captured_at, "", facts
                    )

        return facts, None

    def _extract_record_fact(
        self,
        rec: Dict[str, Any],
        file_id: str,
        file_path: str,
        default_system: str,
        default_timestamp: str,
        collection: str,
        facts: List[EvidenceFact]
    ):
        """Extract a single EvidenceFact from a record dictionary."""
        res_id = rec.get("resource_id", "")
        if not res_id:
            # Check nested document
            if "document" in rec and isinstance(rec["document"], dict):
                res_id = rec.get("resource_id") or rec["document"].get("resource_id", "")

        system = rec.get("system") or rec.get("data_store") or default_system
        if not system or system in ("unknown_service", "records_assurance_service"):
            system = self._infer_system_from_id(res_id) if res_id else default_system

        # Identifiers
        user_id = rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference")
        email = rec.get("email") or rec.get("customer_email") or rec.get("requester_email") or rec.get("owner_email")
        phone = rec.get("phone") or rec.get("requester_phone") or rec.get("owner_phone")
        email_hash = rec.get("email_hash")

        # Nested document support
        doc = rec.get("document")
        if isinstance(doc, dict):
            user_id = user_id or doc.get("customer_reference") or doc.get("user_id")
            email = email or doc.get("email")
            phone = phone or doc.get("phone")
            email_hash = email_hash or doc.get("email_hash")

        # If subject_reference looks like an email:
        if user_id and "@" in str(user_id):
            if not email:
                email = user_id
            user_id = None

        timestamp = rec.get("recorded_at") or rec.get("updated_at") or rec.get("captured_at") or default_timestamp

        # Observed state determination
        res_result = str(rec.get("result", "")).upper()
        account_status = str(rec.get("account_status", "")).upper()
        state_val = str(rec.get("state", "")).upper()
        status_code = str(rec.get("status_code", ""))
        message_text = str(rec.get("message_text", ""))

        if res_result == "NOT_FOUND" or status_code == "404" or (rec.get("profile") is None and "profile" in rec):
            observed_state = "ABSENT"
        elif account_status == "DELETED" and not email and not phone and user_id:
            observed_state = "REDACTED"
        elif "[REDACTED]" in message_text or str(rec.get("details", "")) == "[REDACTED]":
            observed_state = "REDACTED"
        elif state_val in ("ANONYMIZED", "BLOCKED", "DISABLED", "ACTIVE", "PRESENT", "ABSENT", "REDACTED"):
            observed_state = state_val
        elif "enabled" in rec:
            observed_state = "ACTIVE" if rec["enabled"] in (1, "1", True, "true", "True") else "DISABLED"
        elif "restore_allowed" in rec:
            observed_state = "ACTIVE" if rec["restore_allowed"] in (1, "1", True, "true", "True") else "BLOCKED"
        elif system == "support_platform" and (rec.get("requester_email") is None and "requester_email" in rec) and (rec.get("requester_name") is None and "requester_name" in rec):
            observed_state = "REDACTED"
        elif system == "analytics_platform" and not email and not phone and not user_id and not email_hash:
            observed_state = "ANONYMIZED"
        else:
            observed_state = "PRESENT"

        category = rec.get("record_type") or collection or None
        if not category:
            if system == "account_service":
                category = "USER_PROFILE"
            elif system == "search_service":
                category = "SEARCH_INDEX_ENTRY"
            elif system == "analytics_platform":
                category = "ANALYTICS_PROFILE"
            elif system == "support_platform":
                category = "SUPPORT_MESSAGE"
            elif system == "export_service":
                category = "USER_EXPORT"
            elif system == "integration_service":
                category = "DATA_FLOW"
            elif system == "backup_service":
                category = "BACKUP_ARCHIVE"
            elif system == "security_service":
                category = "SECURITY_AUDIT_LOG"

        facts.append(EvidenceFact(
            file_id=file_id,
            source_path=file_path,
            system_id=system,
            resource_id=res_id,
            data_category=category,
            user_id=user_id,
            email=email,
            phone=phone,
            email_hash=email_hash,
            observed_state=observed_state,
            captured_at=default_timestamp,
            event_timestamp=timestamp,
            raw_excerpt=f"json_record: {res_id} sys={system} state={observed_state} email={email} user={user_id}",
            extra_metadata=rec
        ))

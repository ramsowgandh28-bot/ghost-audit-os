"""Log evidence parser for service logs, diagnostic readbacks, and traces."""

import os
import re
from typing import List, Tuple, Optional, Dict

try:
    from ..evidence_record import EvidenceFact
except (ImportError, ValueError):
    from evidence_record import EvidenceFact


class LogEvidenceParser:
    """Parses system and service log files into EvidenceFact instances."""

    # Key-value pattern matching: key="value" or key=value
    KV_REGEX = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')
    TIMESTAMP_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")

    def parse_file(
        self,
        file_id: str,
        file_path: str,
        absolute_path: str,
        captured_at: str
    ) -> Tuple[List[EvidenceFact], Optional[str]]:
        """Parse a service log file line-by-line and extract structured facts.

        Returns:
            Tuple of (facts_list, error_message)
        """
        if not os.path.exists(absolute_path):
            return [], f"File not found: {absolute_path}"

        try:
            with open(absolute_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            return [], f"Failed to read log file {file_id}: {e}"

        facts: List[EvidenceFact] = []

        # First pass: parse lines and collect key-values
        parsed_lines = []
        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            ts_match = self.TIMESTAMP_REGEX.match(line)
            line_ts = ts_match.group(0) if ts_match else captured_at

            kv_dict: Dict[str, str] = {}
            for match in self.KV_REGEX.finditer(line):
                key = match.group(1)
                val = match.group(2) if match.group(2) is not None else match.group(3)
                kv_dict[key] = val

            parsed_lines.append((line_no, line, line_ts, kv_dict))

        # Check if file has trace_ids
        trace_groups: Dict[str, List[Tuple[int, str, str, Dict[str, str]]]] = {}
        non_trace_lines = []
        for item in parsed_lines:
            tid = item[3].get("trace_id")
            if tid:
                trace_groups.setdefault(tid, []).append(item)
            else:
                non_trace_lines.append(item)

        # Process trace groups
        for tid, t_items in trace_groups.items():
            merged_kv: Dict[str, str] = {}
            combined_ts = t_items[0][2]
            primary_line = t_items[0][1]
            primary_line_no = t_items[0][0]

            for l_no, raw_l, l_ts, kv in t_items:
                merged_kv.update(kv)
                combined_ts = l_ts  # use completion timestamp if available

            fact = self._build_fact_from_kv(
                merged_kv, file_id, file_path, captured_at, combined_ts, primary_line, primary_line_no
            )
            if fact:
                facts.append(fact)

        # Process non-trace lines
        for line_no, line, line_ts, kv_dict in non_trace_lines:
            fact = self._build_fact_from_kv(
                kv_dict, file_id, file_path, captured_at, line_ts, line, line_no
            )
            if fact:
                facts.append(fact)

        return facts, None

    def _build_fact_from_kv(
        self,
        kv_dict: Dict[str, str],
        file_id: str,
        file_path: str,
        captured_at: str,
        event_ts: str,
        raw_line: str,
        line_no: int
    ) -> Optional[EvidenceFact]:
        """Build an EvidenceFact from a key-value dictionary."""
        res_id = kv_dict.get("resource_id", "")
        service = kv_dict.get("service", "")
        event = kv_dict.get("event", "")

        user_id = None
        email = None
        phone = None
        email_hash = None

        id_fields = (
            "subject_key", "matched_value", "subject_ref", "lookup_key",
            "correlation_key", "match_key", "subject_reference",
            "customer_reference", "customer_email", "requester_email", "email"
        )
        for id_field in id_fields:
            val = kv_dict.get(id_field)
            if not val or val.lower() == "null":
                continue
            val_clean = val.strip()
            if "@" in val_clean:
                email = val_clean
            elif val_clean.startswith("user_"):
                user_id = val_clean
            elif val_clean.startswith("+") or (any(c.isdigit() for c in val_clean) and len(val_clean) >= 7 and " " in val_clean):
                phone = val_clean
            elif len(val_clean) == 64 and all(c in "0123456789abcdefABCDEF" for c in val_clean):
                email_hash = val_clean

        # Determine observed state
        rows = kv_dict.get("rows")
        http_status = kv_dict.get("http_status")
        result = kv_dict.get("result", "").lower()
        detector = kv_dict.get("detector")
        enabled = kv_dict.get("enabled", "").lower()
        restore_allowed = kv_dict.get("restore_allowed", "").lower()
        deletion_block = kv_dict.get("deletion_block", "").lower()

        observed_state = "PRESENT"
        is_claim = False

        if rows == "0" or http_status == "404" or result == "miss":
            observed_state = "ABSENT"
        elif rows == "1" or http_status == "200" or result == "hit":
            observed_state = "PRESENT"
        elif enabled in ("true", "1"):
            observed_state = "ACTIVE"
        elif enabled in ("false", "0"):
            observed_state = "DISABLED"
        elif restore_allowed in ("false", "0") or deletion_block in ("true", "1"):
            observed_state = "BLOCKED"
        elif restore_allowed in ("true", "1") or deletion_block in ("false", "0"):
            observed_state = "ACTIVE"
        elif service == "analytics_platform":
            req_email = kv_dict.get("email")
            cust_ref = kv_dict.get("customer_reference")
            if (req_email in (None, "null", "")) and (cust_ref in (None, "null", "")):
                observed_state = "ANONYMIZED"
            else:
                observed_state = "PRESENT"
        elif service == "support_platform":
            req_email = kv_dict.get("requester_email")
            req_name = kv_dict.get("requester_name")
            if req_email in (None, "null", "") and req_name in (None, "null", ""):
                observed_state = "REDACTED"
            else:
                observed_state = "PRESENT"
        elif service == "security_service":
            observed_state = "PRESENT"
        elif detector == "direct_identifier" or event in ("message_pii_scan", "attachment_pii_scan"):
            observed_state = "PRESENT"
        elif event == "audit_record_read_completed" and kv_dict.get("integrity_check") == "passed":
            observed_state = "PRESENT"
        else:
            is_claim = True

        # Only emit fact if we have an identifiable entity or resource
        if not res_id and not email and not user_id and not phone:
            return None

        # Data category mapping
        category = None
        if service == "account_service":
            category = "USER_PROFILE"
        elif service == "search_service":
            category = "SEARCH_INDEX_ENTRY"
        elif service == "analytics_platform":
            category = "ANALYTICS_PROFILE"
        elif service == "support_platform":
            category = "SUPPORT_MESSAGE"
        elif service == "integration_service":
            category = "DATA_FLOW"
        elif service == "backup_service":
            category = "BACKUP_ARCHIVE"
        elif service == "security_service":
            category = "SECURITY_AUDIT_LOG"
        elif service == "export_service":
            category = "USER_EXPORT"

        return EvidenceFact(
            file_id=file_id,
            source_path=file_path,
            system_id=service or "observability_log",
            resource_id=res_id or f"log_entry_{line_no}",
            data_category=category,
            user_id=user_id,
            email=email,
            phone=phone,
            email_hash=email_hash,
            observed_state=observed_state,
            captured_at=captured_at,
            event_timestamp=event_ts,
            raw_excerpt=raw_line[:120],
            is_claim=is_claim,
            extra_metadata={"event": event, "level": kv_dict.get("level"), "line_no": line_no}
        )

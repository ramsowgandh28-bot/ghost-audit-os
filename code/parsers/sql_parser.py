"""SQL evidence parser using in-memory SQLite.

Parses SQLite-compatible SQL snapshots representing primary, replica, regional,
reporting, and failover databases. Extracts structured records across all tables.
Ensures records present in any replica are detected.
"""

import os
import sqlite3
import json
import re
from typing import List, Tuple, Optional

try:
    from ..evidence_record import EvidenceFact
except (ImportError, ValueError):
    from evidence_record import EvidenceFact


class SqlEvidenceParser:
    """Parses SQL snapshot exports into structured EvidenceFact instances."""

    def parse_file(
        self,
        file_id: str,
        file_path: str,
        absolute_path: str,
        captured_at: str
    ) -> Tuple[List[EvidenceFact], Optional[str]]:
        """Execute the SQL file in an isolated in-memory SQLite database and extract records.

        Returns:
            Tuple of (facts_list, error_message)
        """
        if not os.path.exists(absolute_path):
            return [], f"File not found: {absolute_path}"

        try:
            with open(absolute_path, "r", encoding="utf-8", errors="replace") as f:
                sql_content = f.read()
        except Exception as e:
            return [], f"Failed to read SQL file: {e}"

        facts: List[EvidenceFact] = []
        conn = sqlite3.connect(":memory:")
        try:
            # Execute script in isolated SQLite database
            conn.executescript(sql_content)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Inspect available tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            for tbl in tables:
                if tbl in ("snapshot_scope", "sqlite_sequence"):
                    continue

                cursor.execute(f'SELECT * FROM "{tbl}"')
                rows = cursor.fetchall()

                for row in rows:
                    d = dict(row)
                    res_id = d.get("resource_id", "")
                    user_ref = d.get("customer_reference") or d.get("user_id") or d.get("subject_reference")
                    email = d.get("email") or d.get("requester_email") or d.get("owner_email") or d.get("customer_email")
                    phone = d.get("phone") or d.get("requester_phone") or d.get("owner_phone")
                    email_hash = d.get("email_hash")
                    status = d.get("account_status", "PRESENT")
                    updated_at = d.get("updated_at", captured_at)
                    origin_sys = d.get("origin_system", "")
                    collection = d.get("collection_name", "")

                    # If record_json is present, parse embedded JSON
                    if "record_json" in d and d["record_json"]:
                        try:
                            rec_doc = json.loads(d["record_json"])
                            if isinstance(rec_doc, dict):
                                res_id = res_id or rec_doc.get("resource_id", "")
                                user_ref = user_ref or rec_doc.get("customer_reference") or rec_doc.get("user_id") or rec_doc.get("subject_reference")
                                email = email or rec_doc.get("email") or rec_doc.get("customer_email") or rec_doc.get("requester_email") or rec_doc.get("owner_email")
                                phone = phone or rec_doc.get("phone") or rec_doc.get("requester_phone") or rec_doc.get("owner_phone")
                                email_hash = email_hash or rec_doc.get("email_hash")
                                status = rec_doc.get("account_status") or status
                        except Exception:
                            pass

                    # Determine system and category based on origin_system, collection, or table name
                    system_id = origin_sys or "account_service"
                    data_category = "USER_PROFILE"
                    obs_state = "PRESENT"

                    tbl_lower = tbl.lower()
                    coll_lower = collection.lower()

                    if coll_lower == "customer_profiles" or tbl_lower.startswith("customer_profiles") or (tbl_lower.startswith("customer_data") and not origin_sys):
                        system_id = origin_sys or "account_service"
                        data_category = "USER_PROFILE"
                        if status == "DELETED" and not email and not phone and user_ref:
                            obs_state = "REDACTED"
                        else:
                            obs_state = "PRESENT"

                    elif coll_lower == "customer_search_documents" or tbl_lower.startswith("customer_search_documents") or tbl_lower.startswith("search_documents"):
                        system_id = origin_sys or "search_service"
                        data_category = "SEARCH_INDEX_ENTRY"
                        obs_state = "PRESENT"

                    elif coll_lower == "customer_analytics_reports" or tbl_lower.startswith("customer_analytics_profiles") or tbl_lower.startswith("analytics"):
                        system_id = origin_sys or "analytics_platform"
                        data_category = "ANALYTICS_PROFILE"
                        has_pii = bool(email or phone or user_ref or email_hash)
                        obs_state = "PRESENT" if has_pii else "ANONYMIZED"

                    elif coll_lower == "security_audit_events" or tbl_lower.startswith("security_audit_records") or tbl_lower.startswith("security"):
                        system_id = origin_sys or "security_service"
                        data_category = "SECURITY_AUDIT_LOG"
                        obs_state = "PRESENT"

                    elif coll_lower == "support_messages" or tbl_lower.startswith("support_records") or tbl_lower.startswith("support"):
                        system_id = origin_sys or "support_platform"
                        data_category = "SUPPORT_MESSAGE"
                        obs_state = "PRESENT"

                    elif coll_lower == "customer_exports" or tbl_lower.startswith("customer_exports") or tbl_lower.startswith("export"):
                        system_id = origin_sys or "export_service"
                        data_category = "USER_EXPORT"
                        obs_state = "PRESENT"

                    elif tbl_lower.startswith("connector_subscriptions") or tbl_lower.startswith("connector"):
                        system_id = origin_sys or "integration_service"
                        data_category = "DATA_FLOW"
                        enabled = int(d.get("enabled", 0)) if "enabled" in d else 0
                        obs_state = "ACTIVE" if enabled == 1 else "DISABLED"

                    elif tbl_lower.startswith("backup_restore_entries") or tbl_lower.startswith("backup"):
                        system_id = origin_sys or "backup_service"
                        data_category = "BACKUP_ARCHIVE"
                        restore_allowed = int(d.get("restore_allowed", 0)) if "restore_allowed" in d else 0
                        obs_state = "ACTIVE" if restore_allowed == 1 else "BLOCKED"

                    elif tbl_lower.startswith("security_audit_records") or tbl_lower.startswith("security"):
                        system_id = "security_service"
                        data_category = "SECURITY_AUDIT_LOG"
                        obs_state = "PRESENT"

                    # Determine replica topology tag
                    topology = "primary"
                    if "replica" in tbl_lower:
                        topology = "replica"
                    if "failover" in tbl_lower:
                        topology = "failover_replica"
                    elif "regional" in tbl_lower or "_eu_" in tbl_lower or "_ap_" in tbl_lower:
                        topology = "regional_replica"
                    elif "reporting" in tbl_lower:
                        topology = "reporting_replica"
                    elif "read" in tbl_lower:
                        topology = "read_replica"

                    facts.append(EvidenceFact(
                        file_id=file_id,
                        source_path=file_path,
                        system_id=system_id,
                        resource_id=res_id,
                        data_category=data_category,
                        user_id=user_ref,
                        email=email,
                        phone=phone,
                        email_hash=email_hash,
                        observed_state=obs_state,
                        captured_at=captured_at,
                        event_timestamp=updated_at,
                        raw_excerpt=f"table={tbl} res={res_id} email={email} user={user_ref} state={obs_state}",
                        extra_metadata={"table": tbl, "topology": topology, "status": status, "row": d}
                    ))

            return facts, None
        except Exception as e:
            return facts, f"SQLite execution error in {file_id}: {e}"
        finally:
            conn.close()

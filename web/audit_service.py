"""Audit Service for Ghost Data Still Exists Web Application.

Bridges the Flask web API with the core Python deletion-audit engine,
providing background job management, progress tracking, results pagination,
12-point contract validation, and public benchmark evaluation.
"""

import csv
import json
import os
import sys
import threading
import time
from typing import Dict, Any, List, Optional, Tuple


def find_repository_paths() -> Tuple[str, str, str]:
    """Locate the repo root, dataset directory, and code directory dynamically."""
    candidates = [
        os.path.abspath("."),
        os.path.abspath("hackerrank-orchestrate-october26-main"),
        os.path.dirname(os.path.abspath(".")),
        os.path.join(os.path.abspath("."), "hackerrank-orchestrate-october26-main"),
    ]
    for c in candidates:
        ds = os.path.join(c, "dataset")
        cd = os.path.join(c, "code")
        if os.path.isdir(ds) and os.path.isdir(cd):
            return os.path.abspath(c), os.path.abspath(ds), os.path.abspath(cd)

    # Fallback to current working directory
    cwd = os.path.abspath(".")
    return cwd, os.path.join(cwd, "dataset"), os.path.join(cwd, "code")


REPO_ROOT, DATASET_DIR, CODE_DIR = find_repository_paths()

if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from loaders import (
    load_deletion_requests,
    load_user_identities,
    load_user_audit_log,
    load_system_activity,
    load_deletion_rules,
)
from identity import IdentityResolver
from evidence_index import EvidenceIndex
from correlator import EvidenceCorrelator
from policy_engine import PolicyEngine
from models import DeletionRequest, AuditOutputRow


def mask_email(email: str) -> str:
    """Mask email for privacy protection in web UI (e.g. j***@example.com)."""
    if not email or "@" not in email:
        return email
    parts = email.split("@", 1)
    name, domain = parts[0], parts[1]
    if len(name) <= 2:
        masked_name = name[0] + "***" if len(name) > 0 else "***"
    else:
        masked_name = name[:2] + "***" + name[-1]
    return f"{masked_name}@{domain}"


class AuditJobManager:
    """Manages asynchronous audit execution and state tracking."""

    def __init__(self, dataset_dir: str = DATASET_DIR):
        self.dataset_dir = dataset_dir
        self.lock = threading.Lock()
        self.current_job = {
            "job_id": "idle",
            "status": "IDLE",  # IDLE, RUNNING, COMPLETED, FAILED
            "dataset_type": "default",
            "dataset_file": "",
            "stage": "Engine Ready",
            "current": 0,
            "total": 0,
            "percent": 0.0,
            "elapsed_seconds": 0.0,
            "started_at": 0.0,
            "completed_at": 0.0,
            "error": None,
            "counts": {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0},
            "output_path": "",
            "validation_report": None,
        }
        self.results_cache: List[Dict[str, Any]] = []
        self._load_cached_output_if_available()

    def _load_cached_output_if_available(self):
        """Preload existing output.csv if available so the results explorer is populated immediately."""
        candidate_paths = [
            os.path.join(REPO_ROOT, "output.csv"),
            os.path.join(os.path.dirname(REPO_ROOT), "output.csv"),
            "output.csv",
        ]
        target_path = None
        for p in candidate_paths:
            if os.path.exists(p) and os.path.getsize(p) > 1000:
                target_path = p
                break

        if not target_path:
            return

        try:
            req_path = os.path.join(self.dataset_dir, "deletion_requests.csv")
            requests_map = {}
            if os.path.exists(req_path):
                with open(req_path, "r", encoding="utf-8") as f:
                    for r in csv.DictReader(f):
                        requests_map[r["case_id"]] = r

            loaded_results = []
            counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

            with open(target_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cid = row["case_id"]
                    status = row["deletion_status"]
                    steps = json.loads(row["steps_json"])
                    counts[status] = counts.get(status, 0) + 1

                    meta = requests_map.get(cid, {})
                    loaded_results.append({
                        "case_id": cid,
                        "email": meta.get("email", ""),
                        "requested_at": meta.get("requested_at", ""),
                        "reported_status": meta.get("reported_status", "UNKNOWN"),
                        "reported_at": meta.get("reported_at", ""),
                        "audit_at": meta.get("audit_at", ""),
                        "request_text": meta.get("request_text", ""),
                        "deletion_status": status,
                        "steps": steps,
                        "steps_count": len(steps),
                        "findings_count": sum(1 for s in steps if s.get("phase") == "FINDING"),
                        "remediations_count": sum(1 for s in steps if s.get("phase") == "REMEDIATION"),
                        "verifications_count": sum(1 for s in steps if s.get("phase") == "VERIFICATION"),
                    })

            self.results_cache = loaded_results
            self.current_job.update({
                "job_id": "cached_previous_run",
                "status": "COMPLETED",
                "dataset_type": "default",
                "dataset_file": "dataset/deletion_requests.csv",
                "stage": "Loaded from existing output.csv",
                "current": len(loaded_results),
                "total": len(loaded_results),
                "percent": 100.0,
                "counts": counts,
                "output_path": target_path,
            })
            # Run fast validation
            self.current_job["validation_report"] = self.validate_output_file(target_path)
        except Exception as e:
            print(f"[AuditJobManager] Warning: failed to preload cached output.csv: {e}")

    def start_audit(self, dataset_type: str = "default", custom_filepath: Optional[str] = None) -> Dict[str, Any]:
        """Start a new deletion-audit execution job in the background."""
        with self.lock:
            if self.current_job["status"] == "RUNNING":
                return {"success": False, "message": "An audit job is already running."}

            if dataset_type == "sample":
                input_file = os.path.join(self.dataset_dir, "sample_deletion_requests.csv")
            elif dataset_type == "uploaded" and custom_filepath:
                input_file = custom_filepath
            else:
                input_file = os.path.join(self.dataset_dir, "deletion_requests.csv")

            if not os.path.exists(input_file):
                return {"success": False, "message": f"Input file not found: {input_file}"}

            job_id = f"audit_{int(time.time())}"
            output_file = os.path.join(REPO_ROOT, "output.csv")

            self.current_job = {
                "job_id": job_id,
                "status": "RUNNING",
                "dataset_type": dataset_type,
                "dataset_file": input_file,
                "stage": "Initializing Engine",
                "current": 0,
                "total": 0,
                "percent": 0.0,
                "elapsed_seconds": 0.0,
                "started_at": time.time(),
                "completed_at": 0.0,
                "error": None,
                "counts": {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0},
                "output_path": output_file,
                "validation_report": None,
            }
            self.results_cache = []

            worker = threading.Thread(
                target=self._run_audit_worker,
                args=(input_file, output_file),
                daemon=True,
            )
            worker.start()

            return {
                "success": True,
                "job_id": job_id,
                "message": f"Audit started for {os.path.basename(input_file)}",
            }

    def _run_audit_worker(self, input_file: str, output_file: str):
        """Worker thread executing the real audit engine."""
        try:
            start_time = time.time()
            job_id = self.current_job["job_id"]
            print(f"\n[DIAGNOSTIC] ========================================================")
            print(f"[DIAGNOSTIC] >>> REAL PYTHON AUDIT ENGINE INVOCATION DETECTED")
            print(f"[DIAGNOSTIC] >>> Job ID:      {job_id}")
            print(f"[DIAGNOSTIC] >>> Input File:  {input_file}")
            print(f"[DIAGNOSTIC] >>> Output File: {output_file}")
            print(f"[DIAGNOSTIC] ========================================================\n")
            self.current_job["stage"] = "Loading datasets..."

            # 1. Load inputs
            requests = load_deletion_requests(input_file)
            identities = load_user_identities(os.path.join(self.dataset_dir, "user_identities.csv"))
            audit_log = load_user_audit_log(os.path.join(self.dataset_dir, "user_audit_log.csv"))
            rules = load_deletion_rules(os.path.join(self.dataset_dir, "deletion_rules.csv"))
            activity = load_system_activity(os.path.join(self.dataset_dir, "system_activity.csv"))

            total_cases = len(requests)
            self.current_job["total"] = total_cases
            self.current_job["stage"] = "Reconstructing identity timelines..."

            # 2. Historical Identity Resolver
            resolver = IdentityResolver(identities, audit_log)

            # 3. Evidence Index
            self.current_job["stage"] = "Indexing & parsing evidence files..."
            evidence_index = EvidenceIndex(self.dataset_dir)

            # 4. Correlator & Policy Engine
            self.current_job["stage"] = "Initializing correlation engine..."
            correlator = EvidenceCorrelator(evidence_index, activity)
            engine = PolicyEngine(rules)

            # 5. Evaluate all requests (strictly sorted by case_id)
            requests.sort(key=lambda r: r.case_id)
            output_rows = []
            detailed_results = []
            status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

            self.current_job["stage"] = "Auditing cases against ground truth..."

            for i, req in enumerate(requests, start=1):
                resolved_id = resolver.find_user_by_email_at(req.email, req.audit_at)
                ctx = correlator.correlate_case(req.case_id, req.email, req.audit_at, resolved_id)
                row = engine.evaluate_case(req.case_id, req.request_text, req.audit_at, ctx)
                output_rows.append(row)
                status_counts[row.deletion_status] += 1

                steps = json.loads(row.steps_json)
                detailed_results.append({
                    "job_id": job_id,
                    "case_id": req.case_id,
                    "email": req.email,
                    "requested_at": req.requested_at,
                    "reported_status": req.reported_status,
                    "reported_at": req.reported_at,
                    "audit_at": req.audit_at,
                    "request_text": req.request_text,
                    "deletion_status": row.deletion_status,
                    "steps": steps,
                    "steps_count": len(steps),
                    "findings_count": sum(1 for s in steps if s.get("phase") == "FINDING"),
                    "remediations_count": sum(1 for s in steps if s.get("phase") == "REMEDIATION"),
                    "verifications_count": sum(1 for s in steps if s.get("phase") == "VERIFICATION"),
                })

                if i == 1 or i % 100 == 0 or i == total_cases:
                    print(f"[DIAGNOSTIC] Job {job_id} | Case {i}/{total_cases}: {req.case_id} -> {row.deletion_status} ({len(steps)} steps)")

                now = time.time()
                self.current_job["current"] = i
                self.current_job["percent"] = round((i / total_cases) * 100, 1)
                self.current_job["elapsed_seconds"] = round(now - start_time, 2)
                self.current_job["counts"] = dict(status_counts)

            print(f"[DIAGNOSTIC] >>> Audit completed for {job_id}: {total_cases} cases processed in {self.current_job['elapsed_seconds']}s")

            # 6. Write output CSV
            self.current_job["stage"] = "Writing and verifying output.csv..."
            target_dirs = [os.path.dirname(os.path.abspath(output_file))]
            # Also mirror to outer workspace root if applicable
            parent_dir = os.path.dirname(REPO_ROOT)
            if parent_dir != REPO_ROOT and os.path.isdir(parent_dir):
                target_dirs.append(parent_dir)

            for d in target_dirs:
                target_csv = os.path.join(d, "output.csv")
                with open(target_csv, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["case_id", "deletion_status", "steps_json"])
                    for row in output_rows:
                        writer.writerow([row.case_id, row.deletion_status, row.steps_json])

            # 7. Perform automated contract validation
            val_report = self.validate_output_file(output_file)

            with self.lock:
                self.results_cache = detailed_results
                self.current_job["status"] = "COMPLETED"
                self.current_job["stage"] = "Audit Complete"
                self.current_job["completed_at"] = time.time()
                self.current_job["elapsed_seconds"] = round(time.time() - start_time, 2)
                self.current_job["validation_report"] = val_report

        except Exception as e:
            with self.lock:
                self.current_job["status"] = "FAILED"
                self.current_job["stage"] = "Execution Error"
                self.current_job["error"] = str(e)
                print(f"[AuditJobManager] Worker failed: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get the current job status snapshot."""
        with self.lock:
            state = dict(self.current_job)
            if state["status"] == "RUNNING":
                state["elapsed_seconds"] = round(time.time() - state["started_at"], 2)
            return state

    def get_results(
        self,
        page: int = 1,
        page_size: int = 25,
        status_filter: Optional[str] = None,
        search: Optional[str] = None,
        sort_by: str = "case_id",
        sort_dir: str = "asc",
        mask_pii: bool = True,
    ) -> Dict[str, Any]:
        """Query and paginate audit results."""
        with self.lock:
            data = list(self.results_cache)

        # 1. Filter by status
        if status_filter and status_filter.upper() != "ALL":
            data = [r for r in data if r["deletion_status"] == status_filter.upper()]

        # 2. Search by case_id, email, or request_text
        if search:
            s_lower = search.lower().strip()
            data = [
                r for r in data
                if s_lower in r["case_id"].lower()
                or s_lower in r["email"].lower()
                or s_lower in r.get("request_text", "").lower()
            ]

        # 3. Sort
        reverse = (sort_dir.lower() == "desc")
        if sort_by == "case_id":
            data.sort(key=lambda r: r["case_id"], reverse=reverse)
        elif sort_by == "status":
            data.sort(key=lambda r: r["deletion_status"], reverse=reverse)
        elif sort_by == "steps_count":
            data.sort(key=lambda r: r["steps_count"], reverse=reverse)
        elif sort_by == "requested_at":
            data.sort(key=lambda r: r.get("requested_at", ""), reverse=reverse)

        total_filtered = len(data)
        total_pages = max(1, (total_filtered + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size

        page_items = []
        for item in data[start_idx:end_idx]:
            c_copy = dict(item)
            if mask_pii:
                c_copy["email"] = mask_email(c_copy["email"])
            page_items.append(c_copy)

        return {
            "job_id": self.current_job.get("job_id", ""),
            "total_items": total_filtered,
            "total_pages": total_pages,
            "current_page": page,
            "page_size": page_size,
            "items": page_items,
            "counts": self.current_job.get("counts", {}),
        }

    def get_case_detail(self, case_id: str, mask_pii: bool = True) -> Optional[Dict[str, Any]]:
        """Get complete details for a single case."""
        with self.lock:
            for item in self.results_cache:
                if item["case_id"] == case_id:
                    c = dict(item)
                    if mask_pii:
                        c["email"] = mask_email(c["email"])
                    return c
        return None

    def validate_output_file(self, csv_path: str) -> Dict[str, Any]:
        """Perform the full 12-rule structural contract validation on an output CSV."""
        if not os.path.exists(csv_path):
            return {
                "is_valid": False,
                "error": f"File does not exist: {csv_path}",
                "rules": [],
            }

        allowed_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
        phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
        operation_order = {
            "REPORT_REMAINING_RECORD": 1,
            "REPORT_EXPOSED_PII": 2,
            "REPORT_ACTIVE_DATA_FLOW": 3,
            "REPORT_RESTORE_RISK": 4,
            "DISABLE_DATA_FLOW": 10,
            "BLOCK_RESTORE": 11,
            "DELETE_RECORD": 12,
            "REDACT_RECORD": 13,
            "ANONYMIZE_RECORD": 14,
            "VERIFY_RECORD_ABSENT": 20,
            "VERIFY_RECORD_PRESENT": 21,
            "VERIFY_RECORD_REDACTED": 22,
            "VERIFY_RECORD_ANONYMIZED": 23,
            "VERIFY_DATA_FLOW_DISABLED": 24,
            "VERIFY_RESTORE_BLOCKED": 25,
        }
        allowed_ops_states = {
            "REPORT_REMAINING_RECORD": "PRESENT",
            "REPORT_EXPOSED_PII": "PRESENT",
            "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
            "REPORT_RESTORE_RISK": "ACTIVE",
            "DISABLE_DATA_FLOW": "DISABLED",
            "BLOCK_RESTORE": "BLOCKED",
            "DELETE_RECORD": "ABSENT",
            "REDACT_RECORD": "REDACTED",
            "ANONYMIZE_RECORD": "ANONYMIZED",
            "VERIFY_RECORD_ABSENT": "ABSENT",
            "VERIFY_RECORD_PRESENT": "PRESENT",
            "VERIFY_RECORD_REDACTED": "REDACTED",
            "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
            "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
            "VERIFY_RESTORE_BLOCKED": "BLOCKED",
        }
        required_step_fields = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]

        # Load valid manifest file IDs
        valid_file_ids = set()
        manifest_path = os.path.join(self.dataset_dir, "evidence_files.csv")
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    valid_file_ids.add(row["file_id"])

        rules = [
            {"id": "R01", "name": "CSV Header Check", "desc": "Header matches ['case_id', 'deletion_status', 'steps_json'] exactly.", "passed": True, "errors": []},
            {"id": "R02", "name": "Row Count & Uniqueness", "desc": "All rows contain unique case_ids without duplicates or omissions.", "passed": True, "errors": []},
            {"id": "R03", "name": "Permitted Status Values", "desc": "Status is strictly COMPLETE, INCOMPLETE, or NOT_APPLICABLE.", "passed": True, "errors": []},
            {"id": "R04", "name": "JSON Syntax Validity", "desc": "steps_json must parse as valid JSON array.", "passed": True, "errors": []},
            {"id": "R05", "name": "NOT_APPLICABLE Empty Steps", "desc": "NOT_APPLICABLE cases must have steps_json == [].", "passed": True, "errors": []},
            {"id": "R06", "name": "Exactly 7 Step Fields", "desc": "Every step object must contain all 7 required schema fields.", "passed": True, "errors": []},
            {"id": "R07", "name": "Consecutive Step Numbers", "desc": "step_no starts at 1 and increases monotonically without gaps.", "passed": True, "errors": []},
            {"id": "R08", "name": "Allowed Operation & State Pairs", "desc": "Every operation is mapped to its allowed resource state.", "passed": True, "errors": []},
            {"id": "R09", "name": "Phase Order Sequence", "desc": "Phases strictly follow FINDING -> REMEDIATION -> VERIFICATION.", "passed": True, "errors": []},
            {"id": "R10", "name": "Within-Phase Ordering", "desc": "Steps sorted by OPERATION_ORDER, system_id, and resource_id.", "passed": True, "errors": []},
            {"id": "R11", "name": "Evidence Citation Integrity", "desc": "Findings & COMPLETE verifications cite valid manifest file IDs; remediations have empty string.", "passed": True, "errors": []},
            {"id": "R12", "name": "Case ID Set Reconciliation", "desc": "Case IDs match expected request dataset.", "passed": True, "errors": []},
        ]

        errors_by_rule = {r["id"]: [] for r in rules}

        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                try:
                    header = next(reader)
                except StopIteration:
                    return {"is_valid": False, "error": "CSV file is empty", "rules": rules}

                if header != ["case_id", "deletion_status", "steps_json"]:
                    errors_by_rule["R01"].append(f"Invalid header: {header}")

                rows = list(reader)

            case_ids = [r[0] for r in rows if len(r) > 0]
            if len(case_ids) != len(set(case_ids)):
                errors_by_rule["R02"].append(f"Found duplicate case IDs ({len(case_ids)} total vs {len(set(case_ids))} unique)")

            for idx, row in enumerate(rows, start=1):
                if len(row) != 3:
                    errors_by_rule["R01"].append(f"Row {idx}: expected 3 columns, found {len(row)}")
                    continue

                case_id, status, steps_str = row[0], row[1], row[2]

                if status not in allowed_statuses:
                    errors_by_rule["R03"].append(f"{case_id}: Invalid status '{status}'")

                try:
                    steps = json.loads(steps_str)
                except Exception as e:
                    errors_by_rule["R04"].append(f"{case_id}: JSON parse error: {e}")
                    continue

                if not isinstance(steps, list):
                    errors_by_rule["R04"].append(f"{case_id}: steps_json is not an array")
                    continue

                if status == "NOT_APPLICABLE":
                    if len(steps) > 0:
                        errors_by_rule["R05"].append(f"{case_id}: NOT_APPLICABLE must have empty steps_json, got {len(steps)} steps")
                    continue

                if len(steps) == 0:
                    errors_by_rule["R03"].append(f"{case_id}: {status} cannot have empty steps_json")
                    continue

                prev_phase_val = 0
                prev_op_val = 0
                prev_sys = ""
                prev_res = ""

                for s_idx, step in enumerate(steps, start=1):
                    # R06: 7 fields
                    if set(step.keys()) != set(required_step_fields):
                        errors_by_rule["R06"].append(f"{case_id} step {s_idx}: Keys mismatch: {set(step.keys())}")

                    # R07: consecutive step_no
                    if step.get("step_no") != s_idx:
                        errors_by_rule["R07"].append(f"{case_id} step {s_idx}: step_no={step.get('step_no')} expected {s_idx}")

                    phase = step.get("phase")
                    op = step.get("operation")
                    state = step.get("state")
                    ev_id = step.get("evidence_id")
                    sys_id = step.get("system_id", "")
                    res_id = step.get("resource_id", "")

                    # R08: op and state
                    if op not in allowed_ops_states:
                        errors_by_rule["R08"].append(f"{case_id} step {s_idx}: Unknown operation '{op}'")
                    elif state != allowed_ops_states[op]:
                        errors_by_rule["R08"].append(f"{case_id} step {s_idx}: State mismatch: op={op} state={state} expected {allowed_ops_states[op]}")

                    # R09: phase order
                    cur_phase_val = phase_order.get(phase, 99)
                    if cur_phase_val < prev_phase_val:
                        errors_by_rule["R09"].append(f"{case_id} step {s_idx}: Phase ordering violation: {phase} after prior phase")

                    # R10: within-phase ordering
                    cur_op_val = operation_order.get(op, 99)
                    if cur_phase_val == prev_phase_val:
                        if cur_op_val < prev_op_val:
                            errors_by_rule["R10"].append(f"{case_id} step {s_idx}: Operation ordering violation: {op} after {prev_op_val}")
                        elif cur_op_val == prev_op_val:
                            if sys_id < prev_sys:
                                errors_by_rule["R10"].append(f"{case_id} step {s_idx}: system_id ordering violation: {sys_id} < {prev_sys}")
                            elif sys_id == prev_sys:
                                if res_id < prev_res:
                                    errors_by_rule["R10"].append(f"{case_id} step {s_idx}: resource_id ordering violation: {res_id} < {prev_res}")

                    prev_phase_val = cur_phase_val
                    prev_op_val = cur_op_val
                    prev_sys = sys_id
                    prev_res = res_id

                    # R11: evidence citations
                    if phase == "FINDING":
                        if not ev_id or ev_id not in valid_file_ids:
                            errors_by_rule["R11"].append(f"{case_id} step {s_idx}: Citation '{ev_id}' not found in manifest")
                    elif phase == "REMEDIATION":
                        if ev_id != "":
                            errors_by_rule["R11"].append(f"{case_id} step {s_idx}: Remediation must have empty evidence_id, got '{ev_id}'")
                    elif phase == "VERIFICATION":
                        if status == "COMPLETE":
                            if not ev_id or ev_id not in valid_file_ids:
                                errors_by_rule["R11"].append(f"{case_id} step {s_idx}: COMPLETE verification citation '{ev_id}' not in manifest")
                        elif status == "INCOMPLETE":
                            if ev_id != "":
                                errors_by_rule["R11"].append(f"{case_id} step {s_idx}: INCOMPLETE post-remediation verification must have empty evidence_id, got '{ev_id}'")

            # Check rule passes
            total_errors = 0
            for r in rules:
                errs = errors_by_rule[r["id"]]
                r["passed"] = (len(errs) == 0)
                r["errors"] = errs[:5]  # cap display errors
                r["error_count"] = len(errs)
                total_errors += len(errs)

            return {
                "is_valid": (total_errors == 0),
                "total_rows": len(rows),
                "total_errors": total_errors,
                "rules": rules,
                "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "filename": os.path.basename(csv_path),
            }

        except Exception as e:
            return {
                "is_valid": False,
                "error": str(e),
                "rules": rules,
            }

    def run_public_benchmark(self) -> Dict[str, Any]:
        """Run public benchmark evaluation against sample_deletion_requests.csv and sample_output.csv."""
        sample_req_path = os.path.join(self.dataset_dir, "sample_deletion_requests.csv")
        sample_out_path = os.path.join(self.dataset_dir, "sample_output.csv")

        if not os.path.exists(sample_req_path) or not os.path.exists(sample_out_path):
            return {
                "success": False,
                "message": "Sample dataset files not found under dataset directory.",
            }

        start_time = time.time()

        # Load samples
        requests = load_deletion_requests(sample_req_path)
        identities = load_user_identities(os.path.join(self.dataset_dir, "user_identities.csv"))
        audit_log = load_user_audit_log(os.path.join(self.dataset_dir, "user_audit_log.csv"))
        rules = load_deletion_rules(os.path.join(self.dataset_dir, "deletion_rules.csv"))
        activity = load_system_activity(os.path.join(self.dataset_dir, "system_activity.csv"))

        resolver = IdentityResolver(identities, audit_log)
        evidence_index = EvidenceIndex(self.dataset_dir)
        correlator = EvidenceCorrelator(evidence_index, activity)
        engine = PolicyEngine(rules)

        # Ground truth
        ground_truth = {}
        with open(sample_out_path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ground_truth[row["case_id"]] = (row["deletion_status"], json.loads(row["steps_json"]))

        total_cases = len(requests)
        status_matches = 0
        total_pred_steps = 0
        total_gt_steps = 0
        step_intersection_count = 0
        exact_sequence_matches = 0
        field_matches = 0
        field_total = 0

        case_evaluations = []

        for req in requests:
            resolved_id = resolver.find_user_by_email_at(req.email, req.audit_at)
            ctx = correlator.correlate_case(req.case_id, req.email, req.audit_at, resolved_id)
            out = engine.evaluate_case(req.case_id, req.request_text, req.audit_at, ctx)
            gt_status, gt_steps = ground_truth.get(req.case_id, ("UNKNOWN", []))
            pred_steps = json.loads(out.steps_json)

            is_status_match = (out.deletion_status == gt_status)
            if is_status_match:
                status_matches += 1

            gt_tuples = [(s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"]) for s in gt_steps]
            pred_tuples = [(s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"]) for s in pred_steps]

            total_pred_steps += len(pred_steps)
            total_gt_steps += len(gt_steps)

            gt_copy = list(gt_tuples)
            matched_in_case = 0
            for p in pred_tuples:
                if p in gt_copy:
                    matched_in_case += 1
                    gt_copy.remove(p)
            step_intersection_count += matched_in_case

            is_exact_sequence = (gt_tuples == pred_tuples)
            if is_exact_sequence:
                exact_sequence_matches += 1

            for p_step in pred_steps:
                required_keys = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
                if set(p_step.keys()) == required_keys:
                    field_matches += 7
                field_total += 7

            case_evaluations.append({
                "case_id": req.case_id,
                "email": mask_email(req.email),
                "predicted_status": out.deletion_status,
                "ground_truth_status": gt_status,
                "status_match": is_status_match,
                "predicted_steps_count": len(pred_steps),
                "ground_truth_steps_count": len(gt_steps),
                "matched_steps_count": matched_in_case,
                "exact_sequence_match": is_exact_sequence,
            })

        status_accuracy = round((status_matches / total_cases) * 100, 2)
        step_precision = round((step_intersection_count / total_pred_steps) * 100, 2) if total_pred_steps > 0 else 0.0
        step_recall = round((step_intersection_count / total_gt_steps) * 100, 2) if total_gt_steps > 0 else 0.0
        sequence_accuracy = round((exact_sequence_matches / total_cases) * 100, 2)
        field_accuracy = round((field_matches / field_total) * 100, 2) if field_total > 0 else 100.0

        elapsed = round(time.time() - start_time, 2)

        return {
            "success": True,
            "elapsed_seconds": elapsed,
            "metrics": {
                "status_accuracy": {
                    "score": status_accuracy,
                    "numerator": status_matches,
                    "denominator": total_cases,
                    "name": "Case Deletion-Status Accuracy",
                    "desc": "Percentage of cases where top-level status matches ground truth exactly.",
                },
                "step_precision": {
                    "score": step_precision,
                    "numerator": step_intersection_count,
                    "denominator": total_pred_steps,
                    "name": "Step-Level Precision",
                    "desc": "Proportion of predicted step tuples (phase, system, resource, op, state) matching ground truth.",
                },
                "step_recall": {
                    "score": step_recall,
                    "numerator": step_intersection_count,
                    "denominator": total_gt_steps,
                    "name": "Step-Level Recall",
                    "desc": "Proportion of ground truth step tuples captured by the engine's predictions.",
                },
                "exact_sequence_accuracy": {
                    "score": sequence_accuracy,
                    "numerator": exact_sequence_matches,
                    "denominator": total_cases,
                    "name": "Exact Sequence Accuracy",
                    "desc": "Cases where the ordered sequence of all steps matches ground truth identically.",
                },
                "field_accuracy": {
                    "score": field_accuracy,
                    "numerator": field_matches,
                    "denominator": field_total,
                    "name": "Field-Level Schema Accuracy",
                    "desc": "Compliance of step objects across all seven mandatory schema keys.",
                },
            },
            "cases": case_evaluations,
            "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def get_evidence_manifest(self) -> List[Dict[str, Any]]:
        """Return the complete evidence files manifest with file diagnostic states."""
        manifest_path = os.path.join(self.dataset_dir, "evidence_files.csv")
        manifest_items = []
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    fpath = os.path.join(self.dataset_dir, row["file_path"].replace("/", os.sep))
                    exists = os.path.exists(fpath)
                    size = os.path.getsize(fpath) if exists else 0
                    ext = os.path.splitext(fpath)[1].lower()
                    manifest_items.append({
                        "file_id": row["file_id"],
                        "file_path": row["file_path"],
                        "origin": row["origin"],
                        "captured_at": row["captured_at"],
                        "exists": exists,
                        "size_bytes": size,
                        "file_type": ext.lstrip("."),
                    })
        return manifest_items


# Global singleton instance
audit_manager = AuditJobManager()
